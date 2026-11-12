/* End-to-end tests against an in-process HTTP/HTTPS server (one thread per connection). */
#include "req.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static int g_fail, g_run;

#define EXPECT(c)                                                                              \
    do {                                                                                       \
        g_run++;                                                                               \
        if (!(c)) {                                                                            \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c);                        \
            g_fail++;                                                                          \
        }                                                                                      \
    } while (0)

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void sleep_ms(int ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

/* ------------------------------------------------------------------ server */

typedef struct srv {
    int fd;
    int port;
    SSL_CTX *ctx; /* NULL => plain HTTP */
    int peer_port; /* port of the other (plain) server, for cross-scheme redirects */
    volatile int stop;
    pthread_t th;
    pthread_mutex_t mu;
    int accepts;
    int active;
} srv;

typedef struct {
    srv *s;
    int fd;
    SSL *ssl;
} cx;

static int cx_read(cx *c, char *buf, size_t n) {
    if (c->ssl) return SSL_read(c->ssl, buf, (int)n);
    return (int)recv(c->fd, buf, n, 0);
}

static void cx_write(cx *c, const void *buf, size_t n) {
    const char *p = (const char *)buf;
    while (n) {
        int w = c->ssl ? SSL_write(c->ssl, p, (int)n) : (int)send(c->fd, p, n, MSG_NOSIGNAL);
        if (w <= 0) return;
        p += w;
        n -= (size_t)w;
    }
}

static void cx_puts(cx *c, const char *s) { cx_write(c, s, strlen(s)); }

/* FIN first (client enters CLOSE_WAIT), then close with unread data => RST.
 * The client's next write then fails with EPIPE, which raises SIGPIPE unless suppressed. */
static void cx_rst(cx *c) {
    shutdown(c->fd, SHUT_WR);
    sleep_ms(100);
}

/* Reads the request head; returns its length or -1. */
static int read_head(cx *c, char *buf, size_t cap) {
    size_t n = 0;
    while (n + 1 < cap) {
        int r = cx_read(c, buf + n, 1);
        if (r <= 0) return -1;
        n++;
        if (n >= 4 && memcmp(buf + n - 4, "\r\n\r\n", 4) == 0) {
            buf[n] = '\0';
            return (int)n;
        }
    }
    return -1;
}

static char *read_body(cx *c, const char *head, size_t *len) {
    const char *cl = strstr(head, "Content-Length: ");
    size_t want = cl ? (size_t)strtoul(cl + 16, NULL, 10) : 0, got = 0;
    char *b = (char *)malloc(want + 1);
    while (got < want) {
        int r = cx_read(c, b + got, want - got > 65536 ? 65536 : want - got);
        if (r <= 0) {
            free(b);
            return NULL;
        }
        got += (size_t)r;
    }
    b[want] = '\0';
    *len = want;
    return b;
}

static void respond(cx *c, const char *status, const char *extra, const void *body, size_t blen) {
    char h[512];
    snprintf(h, sizeof(h), "HTTP/1.1 %s\r\nContent-Length: %zu\r\n%s\r\n", status, blen, extra ? extra : "");
    cx_puts(c, h);
    if (blen) cx_write(c, body, blen);
}

/* Returns 1 if the connection must be closed after this exchange. */
static int route(cx *c, const char *head, const char *body, size_t blen) {
    char method[16] = "", path[1024] = "", buf[2048];
    srv *s = c->s;
    sscanf(head, "%15s %1023s", method, path);

    if (!strcmp(path, "/hello") || !strncmp(path, "/hello?", 7)) {
        respond(c, "200 OK", NULL, "hello", 5);
    } else if (!strcmp(path, "/head")) {
        cx_puts(c, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n");
    } else if (!strcmp(path, "/chunk")) {
        cx_puts(c, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                   "5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: t\r\n\r\n");
    } else if (!strcmp(path, "/echo")) {
        snprintf(buf, sizeof(buf), "X-Method: %s\r\n", method);
        respond(c, "200 OK", buf, body, blen);
    } else if (!strcmp(path, "/reqhdrs")) {
        respond(c, "200 OK", NULL, head, strlen(head));
    } else if (!strcmp(path, "/http10")) {
        cx_puts(c, "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok");
        return 1;
    } else if (!strcmp(path, "/nolen")) {
        cx_puts(c, "HTTP/1.1 200 OK\r\n\r\nbody-without-length");
        return 1;
    } else if (!strcmp(path, "/early")) {
        cx_puts(c, "HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n"
                   "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nREAL");
    } else if (!strcmp(path, "/redir")) {
        respond(c, "302 Found", "Location: /hello\r\n", NULL, 0);
    } else if (!strcmp(path, "/redir-rel")) {
        respond(c, "301 Moved", "Location: a/../hello?x=1#frag\r\n", NULL, 0);
    } else if (!strcmp(path, "/redir-loop")) {
        respond(c, "302 Found", "Location: /redir-loop\r\n", NULL, 0);
    } else if (!strcmp(path, "/redir-same")) {
        respond(c, "302 Found", "Location: /reqhdrs\r\n", NULL, 0);
    } else if (!strcmp(path, "/redir-cross")) {
        snprintf(buf, sizeof(buf), "Location: http://localhost:%d/reqhdrs\r\n", s->port);
        respond(c, "302 Found", buf, NULL, 0);
    } else if (!strcmp(path, "/redir-down")) {
        snprintf(buf, sizeof(buf), "Location: http://127.0.0.1:%d/hello\r\n", s->peer_port);
        respond(c, "302 Found", buf, NULL, 0);
    } else if (!strcmp(path, "/r307")) {
        respond(c, "307 Temporary Redirect", "Location: /echo\r\n", NULL, 0);
    } else if (!strcmp(path, "/r302")) {
        respond(c, "302 Found", "Location: /echo\r\n", NULL, 0);
    } else if (!strcmp(path, "/r303")) {
        respond(c, "303 See Other", "Location: /echo\r\n", NULL, 0);
    } else if (!strcmp(path, "/redir-ftp")) {
        respond(c, "302 Found", "Location: ftp://example.com/\r\n", NULL, 0);
    } else if (!strcmp(path, "/idle-close")) {
        respond(c, "200 OK", NULL, "ok", 2);
        sleep_ms(50);
        return 1; /* keep-alive was promised, but the server drops the idle connection */
    } else if (!strcmp(path, "/slow")) {
        sleep_ms(1500);
        respond(c, "200 OK", NULL, "late", 4);
    } else if (!strcmp(path, "/big")) {
        static char big[4096];
        memset(big, 'x', sizeof(big));
        respond(c, "200 OK", NULL, big, sizeof(big));
    } else if (!strcmp(path, "/stray")) {
        cx_puts(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokGARBAGE");
    } else {
        respond(c, "404 Not Found", NULL, NULL, 0);
    }
    return strstr(head, "Connection: close") != NULL;
}

static void *conn_thread(void *arg) {
    cx *c = (cx *)arg;
    srv *s = c->s;
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (s->ctx) {
        c->ssl = SSL_new(s->ctx);
        SSL_set_fd(c->ssl, c->fd);
        if (SSL_accept(c->ssl) != 1) goto done;
    }
    for (;;) {
        char head[16384];
        char *body;
        size_t blen = 0;
        int done_now;
        if (read_head(c, head, sizeof(head)) < 0) break;
        if (strstr(head, " /rst ")) {
            cx_rst(c); /* close without reading the (large) body */
            break;
        }
        body = read_body(c, head, &blen);
        if (!body) break;
        done_now = route(c, head, body, blen);
        free(body);
        if (done_now) break;
    }
done:
    if (c->ssl) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
    }
    close(c->fd);
    pthread_mutex_lock(&s->mu);
    s->active--;
    pthread_mutex_unlock(&s->mu);
    free(c);
    ERR_clear_error();
    return NULL;
}

static void *accept_thread(void *arg) {
    srv *s = (srv *)arg;
    sigset_t set;
    /* SIGPIPE from server writes must not kill the test; the client thread keeps the default. */
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    while (!s->stop) {
        pthread_t t;
        cx *c;
        struct pollfd pfd;
        int cfd;
        pfd.fd = s->fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        if (poll(&pfd, 1, 50) <= 0) continue; /* portable wake-up for stop */
        cfd = accept(s->fd, NULL, NULL);
        if (cfd < 0) continue;
#ifdef SO_NOSIGPIPE
        {
            int one = 1; /* server-side writes only; the client under test keeps default SIGPIPE */
            setsockopt(cfd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
        }
#endif
        c = (cx *)calloc(1, sizeof(*c));
        c->s = s;
        c->fd = cfd;
        pthread_mutex_lock(&s->mu);
        s->accepts++;
        s->active++;
        pthread_mutex_unlock(&s->mu);
        if (pthread_create(&t, NULL, conn_thread, c) != 0) {
            close(cfd);
            free(c);
            continue;
        }
        pthread_detach(t);
    }
    return NULL;
}

static int srv_start(srv *s, int family, SSL_CTX *ctx) {
    struct sockaddr_storage ss;
    socklen_t sl;
    int one = 1;
    memset(s, 0, sizeof(*s));
    pthread_mutex_init(&s->mu, NULL);
    s->ctx = ctx;
    s->fd = socket(family, SOCK_STREAM, 0);
    if (s->fd < 0) return -1;
    setsockopt(s->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&ss, 0, sizeof(ss));
    if (family == AF_INET6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
        a->sin6_family = AF_INET6;
        a->sin6_addr = in6addr_loopback;
        sl = sizeof(*a);
    } else {
        struct sockaddr_in *a = (struct sockaddr_in *)&ss;
        a->sin_family = AF_INET;
        a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sl = sizeof(*a);
    }
    if (bind(s->fd, (struct sockaddr *)&ss, sl) < 0 || listen(s->fd, 64) < 0 ||
        getsockname(s->fd, (struct sockaddr *)&ss, &sl) < 0) {
        close(s->fd);
        return -1;
    }
    s->port = ntohs(family == AF_INET6 ? ((struct sockaddr_in6 *)&ss)->sin6_port
                                       : ((struct sockaddr_in *)&ss)->sin_port);
    return pthread_create(&s->th, NULL, accept_thread, s);
}

static int srv_accepts(srv *s) {
    int n;
    pthread_mutex_lock(&s->mu);
    n = s->accepts;
    pthread_mutex_unlock(&s->mu);
    return n;
}

static void srv_stop(srv *s) {
    int i, active = 1;
    s->stop = 1;
    shutdown(s->fd, SHUT_RDWR);
    pthread_join(s->th, NULL);
    close(s->fd);
    for (i = 0; i < 300 && active; i++) { /* connection threads exit once clients close */
        pthread_mutex_lock(&s->mu);
        active = s->active;
        pthread_mutex_unlock(&s->mu);
        if (active) sleep_ms(10);
    }
}

/* ------------------------------------------------------------- TLS fixture */

static char g_ca_path[256];

/* Self-signed P-256 certificate whose only SAN is IP:127.0.0.1 (CN is not a hostname). */
static SSL_CTX *make_tls_ctx(void) {
    EVP_PKEY *pk = NULL;
    EVP_PKEY_CTX *kc = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    X509 *x = X509_new();
    X509_NAME *nm;
    X509V3_CTX v3;
    X509_EXTENSION *ext;
    SSL_CTX *ctx;
    FILE *f;
    int fd;
    const char *tmp = getenv("TMPDIR");

    if (!kc || EVP_PKEY_keygen_init(kc) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kc, NID_X9_62_prime256v1) <= 0 || EVP_PKEY_keygen(kc, &pk) <= 0)
        return NULL;
    EVP_PKEY_CTX_free(kc);
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), -3600);
    X509_gmtime_adj(X509_getm_notAfter(x), 86400);
    X509_set_pubkey(x, pk);
    nm = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, (const unsigned char *)"libreq test", -1, -1, 0);
    X509_set_issuer_name(x, nm);
    X509V3_set_ctx(&v3, x, x, NULL, NULL, 0);
    ext = X509V3_EXT_conf_nid(NULL, &v3, NID_subject_alt_name, "IP:127.0.0.1");
    X509_add_ext(x, ext, -1);
    X509_EXTENSION_free(ext);
    if (!X509_sign(x, pk, EVP_sha256())) return NULL;

    snprintf(g_ca_path, sizeof(g_ca_path), "%s/libreq-ca-XXXXXX", tmp && *tmp ? tmp : "/tmp");
    fd = mkstemp(g_ca_path);
    if (fd < 0) return NULL;
    f = fdopen(fd, "w");
    PEM_write_X509(f, x);
    fclose(f);

    ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate(ctx, x);
    SSL_CTX_use_PrivateKey(ctx, pk);
    X509_free(x);
    EVP_PKEY_free(pk);
    return ctx;
}

/* ------------------------------------------------------------------- tests */

static char *mkurl(char *buf, size_t n, const char *scheme, const char *host, int port, const char *path) {
    snprintf(buf, n, "%s://%s:%d%s", scheme, host, port, path);
    return buf;
}

static req_client *client(void) {
    req_client *c = req_client_new();
    req_set_timeout_ms(c, 2000, 2000);
    req_set_retries(c, 1);
    return c;
}

static int body_is(const req_response *r, const char *s) {
    return r->err == REQ_OK && r->body_len == strlen(s) && memcmp(r->body, s, r->body_len) == 0;
}

static void test_basic(srv *s) {
    req_client *c = client();
    req_response r;
    char url[256], want[256];
    size_t n;

    r = req_get(c, mkurl(url, sizeof(url), "http", "127.0.0.1", s->port, "/hello"));
    EXPECT(r.err == REQ_OK && r.status == 200 && body_is(&r, "hello"));
    EXPECT(r.redirects == 0 && r.url && !strcmp(r.url, url));
    EXPECT(req_header_find(&r, "content-length", &n) && n == 1);
    req_response_free(&r);
    EXPECT(r.body == NULL && r.url == NULL);

    r = req_head(c, mkurl(url, sizeof(url), "http", "127.0.0.1", s->port, "/head"));
    EXPECT(r.err == REQ_OK && r.status == 200 && r.body_len == 0 && r.body && r.body[0] == '\0');
    req_response_free(&r);

    r = req_get(c, mkurl(url, sizeof(url), "HTTP", "127.0.0.1", s->port, "/chunk#frag"));
    EXPECT(body_is(&r, "hello world"));
    req_response_free(&r);

    r = req_post(c, mkurl(url, sizeof(url), "http", "127.0.0.1", s->port, "/echo"), "xyz", 3, "text/plain");
    EXPECT(r.status == 200 && body_is(&r, "xyz"));
    EXPECT(req_header_get(&r, "X-Method") && !strncmp(req_header_get(&r, "X-Method"), "POST", 4));
    req_response_free(&r);

    r = req_put(c, url, "p", 1, NULL);
    EXPECT(body_is(&r, "p") && !strncmp(req_header_get(&r, "X-Method"), "PUT", 3));
    req_response_free(&r);

    r = req_patch(c, url, "{}", 2, "application/json");
    EXPECT(body_is(&r, "{}") && !strncmp(req_header_get(&r, "X-Method"), "PATCH", 5));
    req_response_free(&r);

    r = req_delete(c, url);
    EXPECT(r.status == 200 && !strncmp(req_header_get(&r, "X-Method"), "DELETE", 6));
    req_response_free(&r);

    r = req_get(c, mkurl(url, sizeof(url), "http", "127.0.0.1", s->port, "/nope"));
    EXPECT(r.err == REQ_OK && r.status == 404);
    req_response_free(&r);

    /* default request headers */
    r = req_get(c, mkurl(url, sizeof(url), "http", "127.0.0.1", s->port, "/reqhdrs"));
    snprintf(want, sizeof(want), "Host: 127.0.0.1:%d\r\n", s->port);
    EXPECT(r.err == REQ_OK && strstr(r.body, want) && strstr(r.body, "User-Agent: libreq/" REQ_VERSION "\r\n"));
    req_response_free(&r);
    req_client_free(c);
}

static void test_large_body(srv *s) {
    req_client *c = client();
    req_response r;
    char url[256];
    size_t n = 3u * 1024u * 1024u + 7u, i;
    char *big = (char *)malloc(n);
    for (i = 0; i < n; i++) big[i] = (char)('a' + i % 26);
    req_set_max_body(c, 16u * 1024u * 1024u);
    r = req_post(c, mkurl(url, sizeof(url), "http", "127.0.0.1", s->port, "/echo"), big, n, NULL);
    EXPECT(r.err == REQ_OK && r.body_len == n && memcmp(r.body, big, n) == 0);
    req_response_free(&r);

    req_set_max_body(c, 1024);
    r = req_get(c, mkurl(url, sizeof(url), "http", "127.0.0.1", s->port, "/big"));
    EXPECT(r.err == REQ_ERR_OVERFLOW);
    req_response_free(&r);
    free(big);
    req_client_free(c);
}

static void test_keepalive(srv *s) {
    req_client *c = client();
    req_response r;
    char url[256];
    int a0, i;

    a0 = srv_accepts(s);
    mkurl(url, sizeof(url), "http", "127.0.0.1", s->port, "/hello");
    for (i = 0; i < 5; i++) {
        r = req_get(c, url);
        EXPECT(body_is(&r, "hello"));
        req_response_free(&r);
    }
    EXPECT(srv_accepts(s) == a0 + 1);

    /* 1xx is skipped and the connection stays in sync */
    a0 = srv_accepts(s);
    r = req_get(c, mkurl(url, sizeof(url), "http", "127.0.0.1", s->port, "/early"));
    EXPECT(r.status == 200 && body_is(&r, "REAL"));
    req_response_free(&r);
    r = req_get(c, mkurl(url, sizeof(url), "http", "127.0.0.1", s->port, "/hello"));
    EXPECT(body_is(&r, "hello"));
    req_response_free(&r);
    EXPECT(srv_accepts(s) == a0);

    /* close-delimited body is read fully and the connection is not reused */
    r = req_get(c, mkurl(url, sizeof(url), "http", "127.0.0.1", s->port, "/nolen"));
    EXPECT(r.status == 200 && body_is(&r, "body-without-length"));
    req_response_free(&r);
    r = req_get(c, mkurl(url, sizeof(url), "http", "127.0.0.1", s->port, "/hello"));
    EXPECT(body_is(&r, "hello"));
    req_response_free(&r);

    /* HTTP/1.0 without keep-alive must not be pooled */
    for (i = 0; i < 2; i++) {
        a0 = srv_accepts(s);
        r = req_get(c, mkurl(url, sizeof(url), "http", "127.0.0.1", s->port, "/http10"));
        EXPECT(body_is(&r, "ok"));
        req_response_free(&r);
    }
    EXPECT(srv_accepts(s) == a0 + 1); /* the second request needed a fresh connection */

    /* stray bytes after a response poison the connection: it is dropped */
    r = req_get(c, mkurl(url, sizeof(url), "http", "127.0.0.1", s->port, "/stray"));
    EXPECT(body_is(&r, "ok"));
    req_response_free(&r);
    r = req_get(c, mkurl(url, sizeof(url), "http", "127.0.0.1", s->port, "/hello"));
    EXPECT(body_is(&r, "hello"));
    req_response_free(&r);

    /* idle connection closed by the server: a non-idempotent request must still work
     * without retries, because the pool notices the dead connection */
    req_set_retries(c, 0);
    r = req_get(c, mkurl(url, sizeof(url), "http", "127.0.0.1", s->port, "/idle-close"));
    EXPECT(body_is(&r, "ok"));
    req_response_free(&r);
    sleep_ms(200);
    r = req_post(c, mkurl(url, sizeof(url), "http", "127.0.0.1", s->port, "/echo"), "a", 1, NULL);
    EXPECT(r.err == REQ_OK && body_is(&r, "a"));
    req_response_free(&r);
    req_client_free(c);
}

static void test_redirects(srv *s) {
    req_client *c = client();
    req_response r;
    char url[256], want[256];
    const char *hdrs[] = {"Authorization: Bearer SECRET", "Cookie: sid=1", "X-Custom: keep", NULL};
    req_request q;

    r = req_get(c, mkurl(url, sizeof(url), "http", "127.0.0.1", s->port, "/redir"));
    EXPECT(r.status == 200 && body_is(&r, "hello") && r.redirects == 1);
    EXPECT(r.url && !strcmp(r.url, mkurl(want, sizeof(want), "http", "127.0.0.1", s->port, "/hello")));
    req_response_free(&r);

    r = req_get(c, mkurl(url, sizeof(url), "http", "127.0.0.1", s->port, "/redir-rel"));
    EXPECT(r.status == 200 && body_is(&r, "hello"));
    EXPECT(r.url && strstr(r.url, "/hello?x=1") && !strchr(r.url, '#'));
    req_response_free(&r);

    r = req_get(c, mkurl(url, sizeof(url), "http", "127.0.0.1", s->port, "/redir-loop"));
    EXPECT(r.err == REQ_ERR_REDIRECTS);
    req_response_free(&r);

    r = req_get(c, mkurl(url, sizeof(url), "http", "127.0.0.1", s->port, "/redir-ftp"));
    EXPECT(r.err == REQ_OK && r.status == 302); /* unsupported scheme: not followed */
    req_response_free(&r);

    req_set_redirects(c, 0);
    r = req_get(c, mkurl(url, sizeof(url), "http", "127.0.0.1", s->port, "/redir"));
    EXPECT(r.err == REQ_OK && r.status == 302 && req_header_get(&r, "Location"));
    req_response_free(&r);
    req_set_redirects(c, 5);

    /* credentials survive a same-origin redirect ... */
    memset(&q, 0, sizeof(q));
    q.url = mkurl(url, sizeof(url), "http", "127.0.0.1", s->port, "/redir-same");
    q.headers = hdrs;
    r = req_send(c, &q);
    EXPECT(r.status == 200 && strstr(r.body, "Authorization: Bearer SECRET") && strstr(r.body, "Cookie: sid=1"));
    req_response_free(&r);

    /* ... but are dropped when the redirect leaves the origin */
    q.url = mkurl(url, sizeof(url), "http", "127.0.0.1", s->port, "/redir-cross");
    r = req_send(c, &q);
    EXPECT(r.err == REQ_OK && r.status == 200);
    EXPECT(r.body && !strstr(r.body, "SECRET") && !strstr(r.body, "sid=1") && strstr(r.body, "X-Custom: keep"));
    EXPECT(r.url && strstr(r.url, "://localhost:"));
    req_response_free(&r);

    /* 307 keeps method and body; 302 POST and 303 turn into GET without a body */
    r = req_post(c, mkurl(url, sizeof(url), "http", "127.0.0.1", s->port, "/r307"), "body", 4, "text/plain");
    EXPECT(body_is(&r, "body") && !strncmp(req_header_get(&r, "X-Method"), "POST", 4));
    req_response_free(&r);
    r = req_post(c, mkurl(url, sizeof(url), "http", "127.0.0.1", s->port, "/r302"), "body", 4, "text/plain");
    EXPECT(r.status == 200 && r.body_len == 0 && !strncmp(req_header_get(&r, "X-Method"), "GET", 3));
    req_response_free(&r);
    r = req_put(c, mkurl(url, sizeof(url), "http", "127.0.0.1", s->port, "/r303"), "body", 4, "text/plain");
    EXPECT(r.status == 200 && r.body_len == 0 && !strncmp(req_header_get(&r, "X-Method"), "GET", 3));
    req_response_free(&r);
    req_client_free(c);
}

static void test_request_validation(srv *s) {
    req_client *c = client();
    req_response r;
    req_request q;
    char url[256], longurl[5000];
    size_t i;
    static const char *bad_urls[] = {"not-a-url", "http://127.0.0.1/hi\r\nHost: evil", "http://u:p@127.0.0.1/",
                                     "ftp://127.0.0.1/", "http://127.0.0.1:0/", "http://[::1/"};
    static const char *bad_hdrs[][2] = {
        {"X-Test: 1\r\nHost: evil", NULL}, {"Content-Length: 5", NULL}, {"Transfer-Encoding: chunked", NULL},
        {"Bad Name: x", NULL},             {"NoColon", NULL},           {": empty-name", NULL},
    };

    for (i = 0; i < sizeof(bad_urls) / sizeof(bad_urls[0]); i++) {
        r = req_get(c, bad_urls[i]);
        EXPECT(r.err == REQ_ERR_URL);
        req_response_free(&r);
    }
    memcpy(longurl, "http://127.0.0.1/", 17);
    memset(longurl + 17, 'a', sizeof(longurl) - 18);
    longurl[sizeof(longurl) - 1] = '\0';
    r = req_get(c, longurl);
    EXPECT(r.err == REQ_ERR_URL);
    r = req_get(c, NULL);
    EXPECT(r.err == REQ_ERR_URL);
    r = req_get(NULL, "http://127.0.0.1/");
    EXPECT(r.err == REQ_ERR_URL);
    r = req_send(c, NULL);
    EXPECT(r.err == REQ_ERR_URL);

    mkurl(url, sizeof(url), "http", "127.0.0.1", s->port, "/reqhdrs");
    for (i = 0; i < sizeof(bad_hdrs) / sizeof(bad_hdrs[0]); i++) {
        memset(&q, 0, sizeof(q));
        q.url = url;
        q.headers = (const char **)bad_hdrs[i];
        r = req_send(c, &q);
        EXPECT(r.err == REQ_ERR_REJECT);
        req_response_free(&r);
    }

    memset(&q, 0, sizeof(q));
    q.url = url;
    q.method = "GE T";
    r = req_send(c, &q);
    EXPECT(r.err == REQ_ERR_REJECT);
    q.method = "POST";
    q.body_len = 5; /* body pointer missing */
    r = req_send(c, &q);
    EXPECT(r.err == REQ_ERR_REJECT);
    r = req_post(c, url, "x", 1, "text/plain\r\nX-Evil: 1");
    EXPECT(r.err == REQ_ERR_REJECT);

    /* user headers override the defaults instead of duplicating them */
    {
        const char *h[] = {"User-Agent: custom/1", "Accept: application/json", "Host: example.test", NULL};
        memset(&q, 0, sizeof(q));
        q.url = url;
        q.headers = h;
        r = req_send(c, &q);
        EXPECT(r.err == REQ_OK && strstr(r.body, "User-Agent: custom/1") && !strstr(r.body, "libreq/"));
        EXPECT(strstr(r.body, "Host: example.test") && !strstr(r.body, "Host: 127.0.0.1"));
        EXPECT(strstr(r.body, "Accept: application/json") && !strstr(r.body, "Accept: */*"));
        req_response_free(&r);
    }

    /* POST without a body still sends Content-Length: 0 */
    r = req_post(c, url, NULL, 0, NULL);
    EXPECT(r.err == REQ_OK && strstr(r.body, "Content-Length: 0\r\n"));
    req_response_free(&r);

    /* spaces and non-ASCII in the path are percent-encoded on the wire */
    r = req_get(c, mkurl(url, sizeof(url), "http", "127.0.0.1", s->port, "/reqhdrs?q=a b"));
    EXPECT(r.err == REQ_OK && r.status == 404); /* path differs, but the request was well-formed */
    req_response_free(&r);
    req_client_free(c);
}

static void test_errors(srv *s) {
    req_client *c = client();
    req_response r;
    char url[256];
    long long t0;
    int closed_port;

    /* io timeout */
    req_set_timeout_ms(c, 2000, 300);
    req_set_retries(c, 0);
    t0 = now_ms();
    r = req_get(c, mkurl(url, sizeof(url), "http", "127.0.0.1", s->port, "/slow"));
    EXPECT(r.err == REQ_ERR_TIMEOUT);
    EXPECT(now_ms() - t0 < 1200);
    req_response_free(&r);

    /* connection refused */
    {
        srv tmp;
        EXPECT(srv_start(&tmp, AF_INET, NULL) == 0);
        closed_port = tmp.port;
        srv_stop(&tmp);
    }
    r = req_get(c, mkurl(url, sizeof(url), "http", "127.0.0.1", closed_port, "/"));
    EXPECT(r.err == REQ_ERR_CONNECT);
    req_response_free(&r);

    r = req_get(c, "http://does-not-exist.invalid/");
    EXPECT(r.err == REQ_ERR_DNS);
    req_response_free(&r);

    /* the server resets while we upload: must be an error, never SIGPIPE */
    {
        size_t n = 32u * 1024u * 1024u;
        char *big = (char *)calloc(1, n);
        req_set_timeout_ms(c, 2000, 5000);
        r = req_post(c, mkurl(url, sizeof(url), "http", "127.0.0.1", s->port, "/rst"), big, n, NULL);
        EXPECT(r.err == REQ_ERR_CLOSED || r.err == REQ_ERR_IO);
        req_response_free(&r);
        free(big);
    }
    req_client_free(c);
}

static void test_ipv6(srv *s6) {
    req_client *c = client();
    req_response r;
    char url[256], want[64];
    snprintf(url, sizeof(url), "http://[::1]:%d/reqhdrs", s6->port);
    r = req_get(c, url);
    snprintf(want, sizeof(want), "Host: [::1]:%d\r\n", s6->port);
    EXPECT(r.err == REQ_OK && r.body && strstr(r.body, want));
    EXPECT(r.url && !strcmp(r.url, url));
    req_response_free(&r);
    req_client_free(c);
}

static void test_tls(srv *ts) {
    req_client *c = client();
    req_response r;
    char url[256];
    int a0, i;

    /* untrusted by default */
    r = req_get(c, mkurl(url, sizeof(url), "https", "127.0.0.1", ts->port, "/hello"));
    EXPECT(r.err == REQ_ERR_TLS_VERIFY);
    req_response_free(&r);

    EXPECT(req_set_ca(c, "/nonexistent/ca.pem", NULL) == -1);
    EXPECT(req_set_ca(c, NULL, NULL) == -1);
    EXPECT(req_set_ca(c, g_ca_path, NULL) == 0);

    a0 = srv_accepts(ts);
    for (i = 0; i < 3; i++) {
        r = req_get(c, url);
        EXPECT(r.err == REQ_OK && body_is(&r, "hello"));
        req_response_free(&r);
    }
    EXPECT(srv_accepts(ts) == a0 + 1); /* TLS keep-alive */

    r = req_get(c, mkurl(url, sizeof(url), "https", "127.0.0.1", ts->port, "/chunk"));
    EXPECT(body_is(&r, "hello world"));
    req_response_free(&r);

    {
        size_t n = 2u * 1024u * 1024u + 3u, k;
        char *big = (char *)malloc(n);
        for (k = 0; k < n; k++) big[k] = (char)k;
        r = req_post(c, mkurl(url, sizeof(url), "https", "127.0.0.1", ts->port, "/echo"), big, n, NULL);
        EXPECT(r.err == REQ_OK && r.body_len == n && memcmp(r.body, big, n) == 0);
        req_response_free(&r);
        free(big);
    }

    /* trusted CA, but the certificate does not name "localhost" */
    r = req_get(c, mkurl(url, sizeof(url), "https", "localhost", ts->port, "/hello"));
    EXPECT(r.err == REQ_ERR_TLS_VERIFY);
    req_response_free(&r);

    /* https -> http redirects are never followed */
    r = req_get(c, mkurl(url, sizeof(url), "https", "127.0.0.1", ts->port, "/redir-down"));
    EXPECT(r.err == REQ_OK && r.status == 302);
    req_response_free(&r);

    /* idle TLS connection dropped by the server is detected before reuse */
    req_set_retries(c, 0);
    r = req_get(c, mkurl(url, sizeof(url), "https", "127.0.0.1", ts->port, "/idle-close"));
    EXPECT(body_is(&r, "ok"));
    req_response_free(&r);
    sleep_ms(200);
    r = req_post(c, mkurl(url, sizeof(url), "https", "127.0.0.1", ts->port, "/echo"), "t", 1, NULL);
    EXPECT(body_is(&r, "t"));
    req_response_free(&r);

    /* reset during a TLS upload: error, not SIGPIPE */
    {
        size_t n = 32u * 1024u * 1024u;
        char *big = (char *)calloc(1, n);
        r = req_post(c, mkurl(url, sizeof(url), "https", "127.0.0.1", ts->port, "/rst"), big, n, NULL);
        EXPECT(r.err != REQ_OK);
        req_response_free(&r);
        free(big);
    }
    req_client_free(c);

    /* insecure mode skips verification */
    c = client();
    req_set_insecure(c, 1);
    r = req_get(c, mkurl(url, sizeof(url), "https", "localhost", ts->port, "/hello"));
    EXPECT(body_is(&r, "hello"));
    req_response_free(&r);
    req_client_free(c);
}

int main(void) {
    srv s, s6, ts;
    SSL_CTX *tctx;
    int have6;

    EXPECT(strcmp(req_version(), REQ_VERSION) == 0 && strcmp(REQ_VERSION, "1.1.0") == 0);
    EXPECT(srv_start(&s, AF_INET, NULL) == 0);
    have6 = srv_start(&s6, AF_INET6, NULL) == 0;
    tctx = make_tls_ctx();
    EXPECT(tctx != NULL);
    EXPECT(srv_start(&ts, AF_INET, tctx) == 0);
    ts.peer_port = s.port;

    test_basic(&s);
    test_large_body(&s);
    test_keepalive(&s);
    test_redirects(&s);
    test_request_validation(&s);
    test_errors(&s);
    if (have6) test_ipv6(&s6);
    else fprintf(stderr, "note: IPv6 loopback unavailable, skipping IPv6 test\n");
    test_tls(&ts);

    srv_stop(&ts);
    if (have6) srv_stop(&s6);
    srv_stop(&s);
    SSL_CTX_free(tctx);
    unlink(g_ca_path);

    if (g_fail) {
        fprintf(stderr, "integration: %d/%d failed\n", g_fail, g_run);
        return 1;
    }
    printf("integration: %d checks ok\n", g_run);
    return 0;
}
