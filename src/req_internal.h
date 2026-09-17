#ifndef REQ_INTERNAL_H
#define REQ_INTERNAL_H

#include "req.h"
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <limits.h>

#ifdef REQ_USE_OPENSSL
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#endif

#define REQ_POOL_MAX 8
#define REQ_HDR_MAX (64u * 1024u)
#define REQ_BODY_DEFAULT (8u * 1024u * 1024u)
#define REQ_LINE_MAX 8192

static inline int req_add_ok(size_t a, size_t b, size_t *out) {
    if (b > SIZE_MAX - a) return 0;
    *out = a + b;
    return 1;
}

static inline int64_t req_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + (int64_t)(ts.tv_nsec / 1000000L);
}

static inline int req_remain_ms(int64_t deadline) {
    int64_t n = deadline - req_now_ms();
    if (n <= 0) return 0;
    if (n > INT_MAX) return INT_MAX;
    return (int)n;
}

int req_has_crlf(const char *s, size_t n);

typedef struct req_url {
    int tls;
    char host[256];
    int port;
    char path[2048]; /* includes query, starts with / */
} req_url;

int req_parse_url(const char *url, req_url *out);

typedef struct req_conn {
    int in_use;
    int fd;
    int tls;
    int port;
    char host[256];
#ifdef REQ_USE_OPENSSL
    SSL *ssl;
#endif
} req_conn;

struct req_client {
    int connect_ms;
    int io_ms;
    int retries;
    int redirects;
    int insecure;
    size_t max_body;
#ifdef REQ_USE_OPENSSL
    SSL_CTX *ctx;
#endif
    req_conn pool[REQ_POOL_MAX];
};

typedef struct req_buf {
    char *p;
    size_t len;
    size_t cap;
} req_buf;

int req_buf_grow(req_buf *b, size_t need);
void req_buf_free(req_buf *b);
int req_buf_append(req_buf *b, const void *s, size_t n);

int req_io_read(req_conn *cn, void *buf, int n, int64_t deadline);
req_err req_io_write_all(req_conn *cn, const void *buf, size_t n, int64_t deadline);
void req_conn_close(req_conn *cn);

req_err req_connect_host(req_client *c, req_conn *cn, const req_url *u, int64_t deadline);

#endif
