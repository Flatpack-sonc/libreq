#ifndef REQ_INTERNAL_H
#define REQ_INTERNAL_H

#include "req.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef REQ_USE_OPENSSL
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#endif

#define REQ_POOL_MAX 8
#define REQ_HDR_MAX (64u * 1024u)
#define REQ_BODY_DEFAULT (8u * 1024u * 1024u)
#define REQ_LINE_MAX 8192
#define REQ_URL_MAX 4096
#define REQ_INFO_MAX 32 /* max interim (1xx) responses before the final one */

#ifdef MSG_NOSIGNAL
#define REQ_SEND_FLAGS MSG_NOSIGNAL
#else
#define REQ_SEND_FLAGS 0
#endif

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

static inline int req_lower(int ch) { return (ch >= 'A' && ch <= 'Z') ? ch - 'A' + 'a' : ch; }

/* RFC 9110 tchar */
static inline int req_is_tchar(unsigned char ch) {
    if ((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) return 1;
    return ch != '\0' && strchr("!#$%&'*+-.^_`|~", ch) != NULL;
}

int req_has_crlf(const char *s, size_t n);
int req_ascii_ieq(const char *a, const char *b, size_t n);
int req_is_token(const char *s, size_t n);

/* ---- URLs ---- */

typedef struct req_url {
    int tls;
    int ipv6; /* host is an IPv6 literal (stored without brackets) */
    char host[256];
    int port;
    char path[REQ_URL_MAX]; /* origin-form request target: path + query, starts with / */
} req_url;

/* 0 on success, -1 if the URL is invalid or too long. */
int req_parse_url(const char *url, req_url *out);
/* Writes "scheme://host[:port]path". 0 on success, -1 if it does not fit. */
int req_format_url(const req_url *u, char *out, size_t outsz);
/* Writes "host" or "[v6]" plus ":port" when not the default port. */
int req_format_authority(const req_url *u, char *out, size_t outsz);
/* RFC 3986 section 5 reference resolution against base. 0 on success. */
int req_resolve_ref(const req_url *base, const char *ref, char *out, size_t outsz);
int req_same_origin(const req_url *a, const req_url *b);

/* ---- buffers ---- */

typedef struct req_buf {
    char *p;
    size_t len;
    size_t cap;
} req_buf;

int req_buf_grow(req_buf *b, size_t need);
void req_buf_free(req_buf *b);
int req_buf_append(req_buf *b, const void *s, size_t n);
int req_buf_puts(req_buf *b, const char *s);

/* ---- connections ---- */

typedef struct req_conn {
    int in_use;
    int fd;
    int tls;
    int port;
    int reused; /* taken from the pool for the current request */
    int64_t last_used;
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
    BIO_METHOD *bio_meth;
#endif
    req_conn pool[REQ_POOL_MAX];
};

/* > 0 bytes, 0 orderly EOF, -1 error, -2 timeout */
int req_io_read(req_conn *cn, void *buf, int n, int64_t deadline);
req_err req_io_write_all(req_conn *cn, const void *buf, size_t n, int64_t deadline);
void req_conn_close(req_conn *cn);
/* 1 if an idle pooled connection still looks usable (no EOF, no stray bytes). */
int req_conn_alive(req_conn *cn);

req_err req_connect_host(req_client *c, req_conn *cn, const req_url *u, int64_t deadline);
#ifdef REQ_USE_OPENSSL
BIO_METHOD *req_bio_method_new(void);
#endif

/* ---- response reader ---- */

typedef struct req_rd {
    req_conn *cn;
    int64_t deadline;
    size_t got; /* total bytes received for this response */
    char tmp[4096];
    size_t tlen;
    size_t toff;
} req_rd;

/* Reads one complete final response (skipping 1xx). On success the header block and body
 * are moved into hdrs / body and *keep_alive says whether the connection may be reused. */
req_err req_read_response(req_rd *rd, const char *method, size_t max_body, req_buf *hdrs,
                          req_buf *body, int *status, int *keep_alive);

#endif
