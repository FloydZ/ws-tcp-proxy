//%LICENSE////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2015 Devchandra M. Leishangthem (dlmeetei at gmail dot com)
//
// Distributed under the MIT License (See accompanying file LICENSE)
//
//////////////////////////////////////////////////////////////////////////

#include <assert.h>
#include <string.h>

#include "evt_tls.h"

evt_endpt_t evt_tls_get_role(const evt_tls_t *t) {
	assert(t != NULL);
#if OPENSSL_VERSION_NUMBER < 0x10002000L
	return t->ssl->server ? ENDPT_IS_SERVER : ENDPT_IS_CLIENT;
#else
	return SSL_is_server(t->ssl) ? ENDPT_IS_SERVER : ENDPT_IS_CLIENT;
#endif
}

void evt_tls_set_role(evt_tls_t *t, evt_endpt_t role) {
	assert(t != NULL && (role == ENDPT_IS_CLIENT || role == ENDPT_IS_SERVER));
	if (ENDPT_IS_SERVER == role) {
		SSL_set_accept_state(t->ssl);
	} else {
		SSL_set_connect_state(t->ssl);
	}
}

SSL_CTX *evt_get_SSL_CTX(const evt_ctx_t *ctx) {
	return ctx->ctx;
}

SSL *evt_get_ssl(const evt_tls_t *tls) {
	return tls->ssl;
}

static void tls_begin(void) {
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
}

evt_tls_t *evt_ctx_get_tls(evt_ctx_t *d_eng) {
	int r = 0;
	evt_tls_t *con = malloc(sizeof(evt_tls_t));
	if (!con) {
		return NULL;
	}
	memset(con, 0, sizeof *con);

	SSL *ssl = SSL_new(d_eng->ctx);
	if (!ssl) {
		free(con);
		return NULL;
	}
	con->ssl = ssl;

	//use default buf size for now.
	r = BIO_new_bio_pair(&(con->ssl_bio), 0, &(con->app_bio), 0);
	if (r != 1) {
		printf("BIO_new_bio_pair error\n");
		//order is important
		SSL_free(ssl);
		ssl = NULL;
		free(con);
		con = NULL;
		return NULL;
	}

	SSL_set_bio(con->ssl, con->ssl_bio, con->ssl_bio);

	QUEUE_INIT(&(con->q));
	QUEUE_INSERT_TAIL(&(d_eng->live_con), &(con->q));

	con->writer = d_eng->writer;
	con->reader = d_eng->reader;
	con->evt_ctx = d_eng;

	return con;
}

void evt_ctx_set_writer(evt_ctx_t *ctx, net_wrtr my_writer) {
	ctx->writer = my_writer;
	assert(ctx->writer != NULL);
}

void evt_tls_set_writer(evt_tls_t *tls, net_wrtr my_writer) {
	tls->writer = my_writer;
	assert(tls->writer != NULL);
}

void evt_ctx_set_reader(evt_ctx_t *ctx, net_rdr my_reader) {
	ctx->reader = my_reader;
	//assert( ctx->reader != NULL);
}

void evt_tls_set_reader(evt_tls_t *tls, net_rdr my_reader) {
	tls->reader = my_reader;
	//assert( ctx->reader != NULL);
}


void evt_ctx_set_nio(evt_ctx_t *ctx, net_rdr my_reader, net_wrtr my_writer) {
	ctx->reader = my_reader;
	//assert( ctx->reader != NULL);

	ctx->writer = my_writer;
	assert(ctx->writer != NULL);
}

int evt_ctx_set_crt_key(evt_ctx_t *tls, const char *crtf, const char *key) {
	SSL_CTX_set_verify(tls->ctx, SSL_VERIFY_NONE, NULL);

	int r = SSL_CTX_use_certificate_file(tls->ctx, crtf, SSL_FILETYPE_PEM);
	if (r != 1) {
		return r;
	}
	tls->cert_set = 1;

	r = SSL_CTX_use_PrivateKey_file(tls->ctx, key, SSL_FILETYPE_PEM);
	if (r != 1) {
		return r;
	}

	r = SSL_CTX_check_private_key(tls->ctx);
	if (r != 1) {
		return r;
	}
	tls->key_set = 1;
	return 1;
}

int evt_ctx_init(evt_ctx_t *tls) {
	tls_begin();

	//Currently we support only TLS, No DTLS
	//XXX SSLv23_method is deprecated change this,
	//Allow evt_ctx_init to take the method as input param,
	//allow others like dtls
	tls->ctx = SSL_CTX_new(SSLv23_method());
	if (!tls->ctx) {
		return -1;
	}

	long options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;
	SSL_CTX_set_options(tls->ctx, options);

//    SSL_CTX_set_mode(tls->ctx, SSL_MODE_AUTO_RETRY
//        | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
//        | SSL_MODE_ENABLE_PARTIAL_WRITE
#if defined(SSL_MODE_RELEASE_BUFFERS)
//        | SSL_MODE_RELEASE_BUFFERS
#endif
	//    );

	tls->cert_set = 0;
	tls->key_set = 0;
	tls->ssl_err_ = 0;
	tls->writer = NULL;
	tls->reader = NULL;

	QUEUE_INIT(&(tls->live_con));
	return 0;
}

int evt_ctx_init_ex(evt_ctx_t *tls, const char *crtf, const char *key) {
	int r = 0;
	r = evt_ctx_init(tls);
	assert(0 == r);
	return evt_ctx_set_crt_key(tls, crtf, key);
}

int evt_ctx_is_crtf_set(evt_ctx_t *t) {
	return t->cert_set;
}

int evt_ctx_is_key_set(evt_ctx_t *t) {
	return t->key_set;
}

static int evt__send_pending(evt_tls_t *conn, void *buf) {
	assert(conn != NULL);
	int pending = BIO_pending(conn->app_bio);
	if (!(pending > 0))
		return 0;

	int p = BIO_read(conn->app_bio, buf, pending);
	assert(p == pending);

	assert(conn->writer != NULL && "You need to set network writer first");
	p = conn->writer(conn, buf, p);
	return p;
}

static int evt__tls__op(evt_tls_t *conn, enum tls_op_type op, void *buf, int sz) {
	int r = 0;
	int bytes = 0;
	char tbuf[16 * 1024] = {0};

	switch (op) {
		case EVT_TLS_OP_HANDSHAKE: {
			r = SSL_do_handshake(conn->ssl);
			if (r <= 0) {
				printf("Current: EVT_TLS_OP_HANDSHAKE\n");
				ERR_print_errors(conn->app_bio);
			}

			bytes = evt__send_pending(conn, tbuf);
			assert(bytes >= 0);
			if (1 == r || 0 == r) {
				assert(conn->hshake_cb != NULL);
				conn->hshake_cb(conn, r);
			}
			break;
		}

		case EVT_TLS_OP_READ: {
			r = SSL_read(conn->ssl, tbuf, sizeof(tbuf));
			if (r <= 0) {
				printf("Current: EVT_TLS_OP_READ\n");
				ERR_print_errors(conn->app_bio);
			}

			bytes = evt__send_pending(conn, tbuf);
			assert(conn->read_cb != NULL);
			conn->read_cb(conn, tbuf, r);
			break;
		}

		case EVT_TLS_OP_WRITE: {
			assert(sz > 0 && "number of bytes to write should be positive\n");
			printf("BYTES SEND: %.*s ::: len: %u\n", sz, (char *) buf, sz);
			r = SSL_write(conn->ssl, buf, sz);

			if (r < 0) {
				int a = SSL_get_error(conn->ssl, r);

				printf("SSL ERROR: %i, %i\n", r, a);

				ERR_print_errors(conn->app_bio);

				char *str = (char *) malloc(1024);
				ERR_error_string(a, str);
				//printf("Error Str: %s\n", str);
				switch (a) {
					case SSL_ERROR_ZERO_RETURN:
						printf("SSL_ERROR_ZERO_RETURN\n");
						break;
					case SSL_ERROR_SYSCALL:
						printf("SSL_ERROR_SYSCALL\n");
						break;
					case SSL_ERROR_WANT_CONNECT:
						printf("SSL_ERROR_WANT_CONNECT\n");
						break;
					case SSL_ERROR_WANT_WRITE:
						printf("SSL_ERROR_WANT_WRITE\n");
						break;
					case SSL_ERROR_WANT_X509_LOOKUP:
						printf("SSL_ERROR_WANT_X509_LOOKUP\n");
						break;
					case SSL_ERROR_SSL:
						printf("SSL_ERROR_SSL\n");
						break;
					case SSL_ERROR_NONE:
						printf("SSL_ERROR_NONE\n");
						break;
				}
			}
			if (r == 0) {
				printf("SSL ERROR: %i\n", r);
			}

			if (0 == r) goto handle_shutdown;
			bytes = evt__send_pending(conn, tbuf);
			if (r > 0 && conn->write_cb) {
				conn->write_cb(conn, r);
			}
			break;
		}

		case EVT_TLS_OP_SHUTDOWN: {
			goto handle_shutdown;
			break;
		}

		default:
			assert(0 && "Unsupported operation");
			break;
	}
	return r;

handle_shutdown:
	r = SSL_shutdown(conn->ssl);
	bytes = evt__send_pending(conn, tbuf);
	if ((1 == r) && conn->close_cb) {
		conn->close_cb(conn, r);
	}
	return r;
}

int evt_tls_feed_data(evt_tls_t *c, void *data, int sz) {
	int rv = BIO_write(c->app_bio, data, sz);
	assert(rv == sz);

	//if handshake is not complete, do it again
	if (SSL_is_init_finished(c->ssl)) {
		rv = evt__tls__op(c, EVT_TLS_OP_READ, NULL, 0);
	} else {
		rv = evt__tls__op(c, EVT_TLS_OP_HANDSHAKE, NULL, 0);
	}
	return rv;
}

int evt_tls_connect(evt_tls_t *con, evt_handshake_cb cb) {
	con->hshake_cb = cb;
	SSL_set_connect_state(con->ssl);
	return evt__tls__op(con, EVT_TLS_OP_HANDSHAKE, NULL, 0);
}

int evt_tls_accept(evt_tls_t *tls, evt_handshake_cb cb) {
	assert(tls != NULL);
	SSL_set_accept_state(tls->ssl);
	tls->hshake_cb = cb;

	//assert( tls->reader != NULL && "You need to set network reader first");
	//char edata[16*1024] = {0};
	//tls->reader(tls, edata, sizeof(edata));
	return 0;
}

int evt_tls_write(evt_tls_t *c, void *msg, int str_len, evt_write_cb on_write) {
	c->write_cb = on_write;
	return evt__tls__op(c, EVT_TLS_OP_WRITE, msg, str_len);
}

// read only register the callback to be made
int evt_tls_read(evt_tls_t *c, evt_read_cb on_read) {
	assert(c != NULL);
	c->read_cb = on_read;
	return 0;
}

int evt_tls_close(evt_tls_t *tls, evt_close_cb cb) {
	assert(tls != NULL);
	tls->close_cb = cb;
	return evt__tls__op(tls, EVT_TLS_OP_SHUTDOWN, NULL, 0);
}

//need impl
int evt_tls_force_close(evt_tls_t *tls, evt_close_cb cb);


int evt_tls_free(evt_tls_t *tls) {
	BIO_free(tls->app_bio);
	tls->app_bio = NULL;

	SSL_free(tls->ssl);
	tls->ssl = NULL;

	QUEUE_REMOVE(&(tls->q));
	QUEUE_INIT(&(tls->q));

	free(tls);
	tls = NULL;
	return 0;
}

void evt_ctx_free(evt_ctx_t *ctx) {
	QUEUE *qh;
	evt_tls_t *tls = NULL;
	assert(ctx != NULL);

	//clean all pending connections
	QUEUE_FOREACH(qh, &ctx->live_con) {
		tls = QUEUE_DATA(qh, evt_tls_t, q);
		evt__tls__op(tls, EVT_TLS_OP_SHUTDOWN, NULL, 0);
	}

	SSL_CTX_free(ctx->ctx);
	ctx->ctx = NULL;

	// ERR_remove_thread_state(NULL);
	ENGINE_cleanup();
	CONF_modules_unload(1);
	ERR_free_strings();
	EVP_cleanup();
	sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
	//SSL_COMP_free_compression_methods();
	CRYPTO_cleanup_all_ex_data();
}


// adapted from Openssl's s23_srvr.c code
int is_tls_stream(const char *bfr, const ssize_t nrd) {
	int is_tls = 0;
	assert(nrd >= 11);
	if ((bfr[0] & 0x80) && (bfr[2] == 1))// SSL2_MT_CLIENT_HELLO
	{
		// SSLv2
		is_tls = 1;
	}
	if ((bfr[0] == 0x16) && (bfr[1] == 0x03) && (bfr[5] == 1) &&
	    ((bfr[3] == 0 && bfr[4] < 5) || (bfr[9] == bfr[1]))) {
		//SSLv3 and above
		is_tls = 1;
	}
	return is_tls;
}
