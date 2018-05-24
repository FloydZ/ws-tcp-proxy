//
//  ws_proxy.c
//  libuv-ws
//
//  Created by Edward Choh on 1/13/2014.
//  Copyright (c) 2014 Edward Choh. All rights reserved.
//

#include <stdbool.h>
#include <stdio.h>
#include <getopt.h>
#include <inttypes.h>
#include <pthread.h>
#include <assert.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "tls.h"
#include "uv_tls.h"
#include "ws_proxy.h"
#include "sha1.h"

/* settings */
static struct sockaddr_in local_addr;
static struct sockaddr_in remote_addr;

uint64_t WSHandled = 0;
uint64_t HTTPHandled = 0;

bool use_tls = false;

#ifdef DEBUG
#define DEBUG_PRINT(fmt, args...) fprintf(stderr, fmt, ## args)
#else
#define DEBUG_PRINT(fmt, args...)
#endif

#define ASSERT(x) assert(x)

static const char* wshash = "                        258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

#define MULTITHREADED
#ifdef NORMALHTTP
extern http_parser_settings settings;
#endif


static void on_local_close(uv_handle_t* peer);
static void on_remote_close(uv_handle_t* peer);
static void ws_handshake_complete_cb(_context *ctx, char *buf, int len);
static void on_remote_connection(uv_connect_t *req, int status);
static void after_local_write(uv_write_t* req, int status);

void TLS_after_local_write(uv_tls_t *tls, int status) {
    if (status == -1) {
        fprintf(stderr, "TLS Socket write error:");
    }

    uv_tls_close((uv_handle_t*)&tls->skt, (uv_close_cb)free);

    //write_req_t* wr;
    //wr = (write_req_t*)&tls->skt;
    //TODO free(wr->buf.base);
    //free(tls);

}

int ws_header_cb(ws_parser* p) {
    DEBUG_PRINT("on_header: %" PRIu64 ", fin: %u, op: %u\n", p->index, p->header.fin, p->header.opcode);
    print_ws_header(&p->header);
    if (p->header.opcode == CLOSE) {
        /* close both connections on CLOSE frame*/
        _context *ctx = (_context*)p->data;
        uv_close((uv_handle_t*)ctx->local, on_local_close);
    }
    return 0;
}

int ws_chunk_cb(ws_parser* p, const char* at, size_t len) {
    DEBUG_PRINT("recv on the WS Socket -> TCP Socket\n");
    DEBUG_PRINT("on_chunk: %" PRIu64 "\t%zu\n", p->index, len);
    xxdprint(at, 0, len);

    /* forward to remote */
    _context *ctx = (_context*)p->data;
    write_req_t *wr;
    wr = malloc(sizeof(write_req_t));
    char *b = malloc(len);
    memcpy(b, at, len);
    wr->buf = uv_buf_init(b, (unsigned int)len);
    uv_write(&wr->req, ctx->remote, &wr->buf, 1, after_local_write);

    return 0;
}

int ws_complete_cb(ws_parser* p) {
    DEBUG_PRINT("on_complete: %" PRIu64 "\n", p->index);
    return 0;
}

void ws_write(_context *ctx, char *buf, size_t len, unsigned int opcode) {
    char *header = malloc(sizeof(char) * 4);
    int hdr_len = ws_encode_bin_hdr(buf, len, header, opcode);
    if (hdr_len) {
        write_req_t *wr;
        wr = malloc(sizeof(write_req_t));
        wr->buf = uv_buf_init(header, hdr_len);
        if (use_tls){
            DEBUG_PRINT("ws_write tls\n");
            uv_tls_write((uv_tls_t*)(ctx->local), &wr->buf, TLS_after_local_write);
        }else{
            //printf("SEND BYTES: %s\n", (char *)&wr->buf);
            uv_write(&wr->req, ctx->local, &wr->buf, 1, after_local_write);
        }

        wr = malloc(sizeof(write_req_t));
        wr->buf = uv_buf_init(buf, (unsigned int)len);
        if (use_tls){
            DEBUG_PRINT("ws_write tls2\n");
            uv_tls_write((uv_tls_t*)(ctx->local), &wr->buf, TLS_after_local_write);
        }else{
            uv_write(&wr->req, ctx->local, &wr->buf, 1, after_local_write);
        }
    }
}

static ws_settings wssettings = {
    .on_header = ws_header_cb,
    .on_chunk = ws_chunk_cb,
    .on_complete = ws_complete_cb,
};

void context_init (uv_stream_t* handle) {
    _context* context = malloc(sizeof(_context));
    context->request = malloc(sizeof(request));
    strcpy(context->request->wskey, wshash);
    context->wsparser = NULL;
    context->request->id = 0;
    context->request->handshake = 0;
    context->local = handle;
    handle->data2 = context;
#ifdef NORMALHTTP
    context->parser = malloc(sizeof(http_parser));
    http_parser_init(context->parser, HTTP_REQUEST);
    context->parser->data = context;

#endif
    context->ws_handshake_complete_cb = ws_handshake_complete_cb;
}

void context_free (uv_handle_t* handle) {
    _context* context = handle->data2;
    if(context) {
        free(context->request);
#ifdef NORMALHTTP
        free(context->parser);
#endif
        free(context->wsparser);
        free(context->pending_response.base);
        if (context->remote)
            uv_close((uv_handle_t*)context->remote, on_remote_close);
        free(context);
    }
    free(handle);
}

void ws_handshake_complete_cb(_context *ctx, char *buf, int len) {
    char *b = (char *)malloc(len);
    memcpy(b, buf, len);
    ctx->pending_response = uv_buf_init(b, len);

    /* connect to remote */
    ctx->remote = malloc(sizeof(uv_tcp_t));
    // WAR int e = uv_tcp_init(loop, (uv_tcp_t*)ctx->remote);
    int e = uv_tcp_init(ctx->local->loop, (uv_tcp_t*)ctx->remote);
    if (e < 0) {
        fprintf(stderr, "Socket creation error: %s", uv_strerror(e));
        return;
    }
    ctx->remote->data2 = ctx;

    uv_connect_t *cr = malloc(sizeof(uv_connect_t));
    e = uv_tcp_connect(cr, (uv_tcp_t*)ctx->remote, (const struct sockaddr*) &remote_addr, on_remote_connection);
    if (e < 0) {
        fprintf(stderr, "Socket creation error2: %s\n", uv_strerror(e));
        return;
    }

    ctx->wsparser = malloc(sizeof(ws_parser));
    ws_init(ctx->wsparser);
    ctx->wsparser->data = ctx;

#ifdef NORMALHTTP
    if(!http_should_keep_alive(ctx->parser)) {
        DEBUG_PRINT("http_should_keep_alive \n");
        uv_close((uv_handle_t*)ctx->local, on_local_close);
    }
#endif
}


static void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
  buf->base = malloc(suggested_size);
  buf->len = suggested_size;
}

/*void uv_rd_cb( uv_stream_t *strm, ssize_t nrd, const uv_buf_t *bfr) {
    printf("TLS write: %s\n", bfr->base);

    if ( nrd <= 0 ) return;
    printf("TLS write: len >0\n");
    uv_tls_write((uv_tls_t*)strm, (uv_buf_t*)bfr, TLS_after_local_write);
}*/


void on_local_close(uv_handle_t* peer) {
    DEBUG_PRINT("local close\n");
    context_free(peer);
}

void on_remote_close(uv_handle_t* peer) {
    /* context does not belong to context, so will not free that here */
    DEBUG_PRINT("remote close\n");
    free(peer);
}

void after_shutdown(uv_shutdown_t* req, int status) {
    uv_close((uv_handle_t*)req->handle, on_local_close);
    free(req);
}

void after_remote_read(uv_stream_t* handle, ssize_t nread, const uv_buf_t *buf) {
    _context *ctx = handle->data2;
    if (nread < 0) {
        DEBUG_PRINT("after_remote_read: <0\n");
        /* disassociate remote connection from context */
        ctx->remote = NULL;
        uv_close((uv_handle_t*)handle, on_remote_close);
        /* close local as well */
        uv_close((uv_handle_t*)ctx->local, on_local_close);
    } else if (nread == 0) {
        DEBUG_PRINT("after_remote_read: =0\n");

        /* disassociate remote connection from context */
        ctx->remote = NULL;
        uv_close((uv_handle_t*)handle, on_remote_close);
        /* close local as well */
        uv_close((uv_handle_t*)ctx->local, on_local_close);
    } else {
        /* forward to local and encode as ws frames */
        //Little Debug Helper
        HTTPHandled++;
        DEBUG_PRINT("recv on the TCP Socket -> WS Socket\n");
        xxdprint(buf->base, 0, nread);
        ws_write(ctx, buf->base, nread, BIN);

        /* buf.base is now queued for sending, do not remove here */
        return;
    }
    free(buf->base);

}

void on_remote_connection(uv_connect_t *req, int status) {
    _context *ctx = req->handle->data2;
    if (status == -1) {
        // error connecting to remote, disconnect local */
        fprintf(stderr, "Remote connect error:\n");
        uv_close((uv_handle_t*)ctx->local, on_local_close);
        free(req);
        return;
    }
    uv_read_start(req->handle, alloc_buffer, after_remote_read);

    /* write the pending_response to local */
    if (ctx->pending_response.base) {
        write_req_t *wr;
        wr = malloc(sizeof(write_req_t));
        wr->buf = ctx->pending_response;
        if (use_tls){
            DEBUG_PRINT("on_remote_connection tls \n");
            uv_tls_write((uv_tls_t*)(ctx->local), &wr->buf, TLS_after_local_write);
        }else{
            uv_write(&wr->req, ctx->local, &wr->buf, 1, after_local_write);
        }
        /* pending_response.base now belongs to wr->buf.base */
        ctx->pending_response.base = NULL;
    }
    if(!use_tls)
        free(req);
}

void after_local_write(uv_write_t* req, int status) {
    write_req_t* wr;
    if (status == -1) {
        fprintf(stderr, "Socket write error:");
    }
    wr = (write_req_t*) req;
    free(wr->buf.base);
    free(wr);

}

#ifndef NORMALHTTP
void parse_headers(request* req,  struct phr_header *headers, int nHeader)
{
    for (int i = 0; i != nHeader; ++i) {
        printf("%.*s: %.*s\n", (int)headers[i].name_len, headers[i].name,
               (int)headers[i].value_len, headers[i].value);
    }
}
#endif
void after_local_read(uv_stream_t* handle, ssize_t nread, const uv_buf_t *buf) {
   #ifndef NORMALHTTP
    const char *msg;
    int pret, minor_version, status;
    struct phr_header headers[100];
    static size_t prevbuflen = 0;
    size_t msg_len, num_headers;
#endif

    if (nread < 0) {
        printf("Read -1\n");
        uv_close((uv_handle_t*)handle, on_local_close);
    } else if (nread == 0) {
        printf("Read 0\n");
        uv_close((uv_handle_t*)handle, on_local_close);
    } else {
        _context *ctx = handle->data2;
        if ( ctx == NULL ) {
           printf("Context not vaild\n");
           return;
        }
        if (ctx->request->handshake == 0) {
#ifdef NORMALHTTP

            size_t np = http_parser_execute(ctx->parser, &settings, buf->base, nread);
            if(np != nread) {
                DEBUG_PRINT("http parser ERROR\n");
                uv_shutdown_t* req;
                req = (uv_shutdown_t*) malloc(sizeof *req);
                uv_shutdown(req, handle, after_shutdown);
            }

#else
            xxdprint(buf->base, 0, nread);
            prevbuflen = nread;
            pret = phr_parse_response(buf->base, nread, &minor_version, &status,
                                      &msg, &msg_len, headers, &num_headers, prevbuflen);

            printf("after_local_read passed\n");


            if(prevbuflen != nread) {
                DEBUG_PRINT("PICOHTTPPARSE ERROR\n");
                uv_shutdown_t* req;
                req = (uv_shutdown_t*) malloc(sizeof *req);
                uv_shutdown(req, handle, after_shutdown);
            }

            printf("%u\n", status);

                //Now write everything
            request* req = ctx->request;
            parse_headers(req, headers, num_headers);

            //req->keepalive = http_should_keep_alive(p);
            req->http_major = 1; //TODO was ist mit 2
            req->http_minor = minor_version;
            req->method = 1; //kb aif strcpy//method;
            req->upgrade = 0;//p->upgrade;
            req->keepalive = status;
            if (pret == -1){
                DEBUG_PRINT("PICOHTTPPARSE FAILED ERROR\n");
            }
#endif
        } else {
            WSHandled++;
            size_t np = ws_execute(ctx->wsparser, &wssettings, buf->base, 0, nread);
            if(np != nread) {
                DEBUG_PRINT("WS EXECUTE ERROR\n");
                uv_shutdown_t* req;
                req = (uv_shutdown_t*) malloc(sizeof *req);
                uv_shutdown(req, handle, after_shutdown);
            }
        }
    }
    if (!use_tls)
        free(buf->base);
}

void on_uv_handshake(uv_tls_t *ut, int status) {
    if ( 0 == status ){
        DEBUG_PRINT("Recv valid tls handshake\n");
        //OLD uv_tls_read((uv_stream_t*)ut, NULL, uv_rd_cb);
        uv_tls_read((uv_stream_t*)ut, alloc_buffer, after_local_read);
    }else{
        DEBUG_PRINT("Recv invalid tls handshake\n");
        uv_tls_close((uv_handle_t*)ut, (uv_close_cb)free);
    }
}

void on_local_connection(uv_stream_t *handle, int status) {
    if (status == -1) {
        fprintf(stderr, "Socket connect error:");
        return;
    }

    if (use_tls == true){
        DEBUG_PRINT("on_local_connection tls\n");

        //uv_stream_t *stream = malloc(sizeof(uv_tcp_t));

        uv_tls_t *sclient = malloc(sizeof(*sclient)); //freed on uv_close callback
        if( uv_tls_init(handle->loop, (evt_ctx_t*)handle->data, sclient) < 0 ) {
            fprintf(stderr, "on_local_connection: TLS uv_tls_init error\n");

            free(sclient);
            return;
        }
        if (!uv_accept(handle, (uv_stream_t*)&(sclient->skt))) {
            context_init((uv_stream_t*)&(sclient->skt));
            uv_tls_accept(sclient, on_uv_handshake);
        }
    }else{
        uv_stream_t *stream = malloc(sizeof(uv_tcp_t));
        //War mal if (uv_tcp_init(loop, (uv_tcp_t*)stream)) {
        if (uv_tcp_init(handle->loop, (uv_tcp_t*)stream)) {
            fprintf(stderr, "on_local_connection: uv_tcp_init error\n");
            return;
        }
        if (uv_accept(handle, stream) == 0) {
            context_init(stream);
            uv_read_start(stream, alloc_buffer, after_local_read);
        } else {
            uv_close((uv_handle_t*)stream, NULL);
        }
    }
}


int server_start(uv_tcp_t *server) {
    evt_ctx_t ctx;
    uv_loop_t* loop;
    loop = uv_loop_new();

    if (use_tls == true){
        evt_ctx_init_ex(&ctx, "server-cert.pem", "server-key.pem");
        evt_ctx_set_nio(&ctx, NULL, uv_tls_writer);
    }

    int e = 0;
    e = uv_tcp_init_ex(loop, server, AF_INET);
    if (e < 0) {
        DEBUG_PRINT("Socket creation error: %s\n",  uv_strerror(e));
        return 1;
    }


    uv_os_fd_t fd;
    int on = 1;
    uv_fileno((const uv_handle_t *)server, &fd);
    e = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (char*)&on, sizeof(on));
    if (e != 0)
    {
        DEBUG_PRINT("setsockopt error: %d\n", errno);
    }

    server->data = &ctx;


    e = uv_tcp_bind(server, (const struct sockaddr*)&local_addr, 0);
    if (e < 0) {
        DEBUG_PRINT("Socket bind error: %s\n", uv_strerror(e));
        return 1;
    }

    e = uv_listen((uv_stream_t*)server, BACKLOG, on_local_connection);
    if (e < 0) {
        DEBUG_PRINT("Socket listen error: %s\n", uv_strerror(e));
        return 1;
    }

    DEBUG_PRINT("Proxying Websocket (%s:%u)", inet_ntoa(local_addr.sin_addr), ntohs(local_addr.sin_port));
    DEBUG_PRINT(" -> TCP (%s:%u) TLS: %u\n", inet_ntoa(remote_addr.sin_addr), ntohs(remote_addr.sin_port), use_tls);
    e = uv_run(loop, UV_RUN_DEFAULT);
    uv_loop_delete(loop);

    return 0;
}


int parse_args(int argc, char **argv) {
    memset(&local_addr, '\0', sizeof(struct sockaddr_in));
    memset(&remote_addr, '\0', sizeof(struct sockaddr_in));

    uv_ip4_addr("0.0.0.0", 3042, &local_addr);
    uv_ip4_addr("127.0.0.1", 3323, &remote_addr);

    /* parse command line arguments */
    int c;
    while(1) {
        static struct option long_options[] = {
            {"secure", no_argument, 0, 's'},
            {"remote", required_argument, 0, 'r'},
            {"local", required_argument, 0, 'l'},
            {0, 0, 0, 0},
        };

        int option_index = 0;

        c = getopt_long(argc, argv, "r:l:s:", long_options, &option_index);

        //detect end of options
        if (c == -1)
            break;

        switch(c) {
            case 's':
                DEBUG_PRINT("%s\n", "User SSL");
                use_tls = true;
                break;
            case 'r':
            case 'l': {
                char *colon = strchr(optarg, ':');
                if (colon == NULL)
                    goto usage;
                char *port = colon + 1;
                *colon = '\0';
                struct sockaddr_in addr;
                uv_ip4_addr(optarg, atoi(port), &addr);
                if (c == 'r')
                    memcpy(&remote_addr, &addr, sizeof(struct sockaddr_in));
                else
                    memcpy(&local_addr, &addr, sizeof(struct sockaddr_in));
                break;
            }
            default:
                goto usage;
        }
    }
    return 1;

usage:
    fprintf(stderr, "usage: ws_proxy --local 0.0.0.0:8080 --remote 127.0.0.1:5000\n");
    return 0;
}

void sigintHandler(int s){
    printf("Caught signal %d\n",s);
    printf("WS  : %"PRIu64"\n", WSHandled);
    printf("HTTP: %"PRIu64"\n", HTTPHandled);

    exit(1);

}



//TODO https://github.com/haywire/haywire/tree/master/src/haywire
int main(int argc, char **argv) {

    struct sigaction sigIntHandler;

    sigIntHandler.sa_handler = sigintHandler;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;

    sigaction(SIGINT, &sigIntHandler, NULL);

    int num_threads = 2;
    uv_tcp_t server[num_threads];
    uv_thread_t threads[num_threads];
    uv_loop_t *uv_loop;



    if (parse_args(argc, argv) == 0)
        return 0;

    uv_loop = uv_default_loop();

    uv_async_t* service_handle = 0;
    service_handle = malloc(sizeof(uv_async_t));
    uv_async_init(uv_loop, service_handle, NULL);

    for (int i = 0; i < num_threads; i++)
    {
        int e = uv_thread_create(&threads[i], server_start, &server[i]);
        if (e){
            printf("uv_thread_create error: %u\n", e);
            return 0 ;
        }
    }

    uv_run(uv_loop, UV_RUN_DEFAULT);

    return 0;
}
