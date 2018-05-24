OPT_FAST=-Wall -I./http-parser  -I./libuv/include -g -msse3 -msha -DDEBUG
LFLAGS := -lm -lpthread -lrt -lssl -lcrypto
CC=gcc

FLAGS = -O3 -march=native  #unused
#unused
# worker.c dispatcher.c

HTTP= -DNORMALHTTP -DHTTP_PARSER_STRICT=1 -DHTTP_PARSER_DEBUG=1  http.c http-parser/http_parser.c
#HTTP= picohttpparser/picohttpparser.c -I./picohttpparser

ws_proxy: libuv/uv.a
	$(CC) $(OPT_FAST) -o ws_proxy  $(HTTP) ws_proxy.c sha1.c  wsparser.c tls.c evt_tls.c uv_tls.c libuv/libuv.a $(LFLAGS)

libuv/uv.a:
	$(MAKE) -C libuv -j4
	cp libuv/.libs/libuv.a libuv/libuv.a

clean:
	rm -f libuv/libuv.a
	rm -f http-parser/http_parser.o
	rm -f ws_proxy
