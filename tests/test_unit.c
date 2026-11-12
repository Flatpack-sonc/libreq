/* Deterministic unit tests for the URL parser, reference resolution and the response
 * parser. Links against the static library and uses its internal header. */
#include "../src/req_internal.h"

#include <pthread.h>
#include <sys/socket.h>

static int g_fail, g_run;

#define EXPECT(c)                                                                              \
    do {                                                                                       \
        g_run++;                                                                               \
        if (!(c)) {                                                                            \
            fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c);                        \
            g_fail++;                                                                          \
        }                                                                                      \
    } while (0)

#define EXPECT_MSG(c, ...)                                                                     \
    do {                                                                                       \
        g_run++;                                                                               \
        if (!(c)) {                                                                            \
            fprintf(stderr, "FAIL %s:%d ", __FILE__, __LINE__);                                \
            fprintf(stderr, __VA_ARGS__);                                                      \
            fputc('\n', stderr);                                                               \
            g_fail++;                                                                          \
        }                                                                                      \
    } while (0)

/* ------------------------------------------------------------------ URLs */

static void test_parse_ok(void) {
    static const struct {
        const char *in, *host, *path;
        int tls, port, ipv6;
    } ok[] = {
        {"http://example.com", "example.com", "/", 0, 80, 0},
        {"https://h", "h", "/", 1, 443, 0},
        {"HTTP://Example.COM/A", "example.com", "/A", 0, 80, 0},
        {"http://h:8080?x=1", "h", "/?x=1", 0, 8080, 0},
        {"http://h:/p", "h", "/p", 0, 80, 0},
        {"http://h/p#frag", "h", "/p", 0, 80, 0},
        {"http://h#frag", "h", "/", 0, 80, 0},
        {"http://h/a b?q=\xc3\xa9", "h", "/a%20b?q=%C3%A9", 0, 80, 0},
        {"http://h/\"<x>`", "h", "/%22%3Cx%3E%60", 0, 80, 0},
        {"http://[::1]:8443/x", "::1", "/x", 0, 8443, 1},
        {"https://[2001:db8::1]/", "2001:db8::1", "/", 1, 443, 1},
        {"http://10.0.0.1:1/", "10.0.0.1", "/", 0, 1, 0},
        {"http://h:65535/", "h", "/", 0, 65535, 0},
        {"http://my_host.local/", "my_host.local", "/", 0, 80, 0},
    };
    size_t i;
    for (i = 0; i < sizeof(ok) / sizeof(ok[0]); i++) {
        req_url u;
        int rc = req_parse_url(ok[i].in, &u);
        EXPECT_MSG(rc == 0, "parse %s", ok[i].in);
        if (rc) continue;
        EXPECT_MSG(!strcmp(u.host, ok[i].host), "%s host=%s", ok[i].in, u.host);
        EXPECT_MSG(!strcmp(u.path, ok[i].path), "%s path=%s", ok[i].in, u.path);
        EXPECT_MSG(u.tls == ok[i].tls && u.port == ok[i].port && u.ipv6 == ok[i].ipv6, "%s flags", ok[i].in);
    }
}

static void test_parse_bad(void) {
    static const char *bad[] = {
        "", "ftp://h/", "http:/h", "http://", "http:///p", "h/p", "//h/p",
        "http://u:p@h/", "http://u@h/", "http://h:0/", "http://h:65536/", "http://h:12a/",
        "http://h:123456/", "http://[::1/", "http://[zz]/", "http://[::1]x/", "http://[]/",
        "http://[fe80::1%25eth0]/", "http://h\r\n/", "http://h/\r\nX: y", "http://h o/",
        "http://h/\x01", "http://h/\x7f", "http://h%2f/", "http://h\\@evil/",
    };
    size_t i;
    char longurl[REQ_URL_MAX + 16];
    req_url u;
    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        EXPECT_MSG(req_parse_url(bad[i], &u) != 0, "accepted bad url %s", bad[i]);
    }
    EXPECT(req_parse_url(NULL, &u) != 0);
    memcpy(longurl, "http://h/", 9);
    memset(longurl + 9, 'a', sizeof(longurl) - 10);
    longurl[sizeof(longurl) - 1] = '\0';
    EXPECT(req_parse_url(longurl, &u) != 0); /* rejected, never truncated */
}

static void test_format(void) {
    req_url u;
    char buf[REQ_URL_MAX];
    EXPECT(req_parse_url("http://[::1]:8443/x?y", &u) == 0);
    EXPECT(req_format_authority(&u, buf, sizeof(buf)) == 0 && !strcmp(buf, "[::1]:8443"));
    EXPECT(req_format_url(&u, buf, sizeof(buf)) == 0 && !strcmp(buf, "http://[::1]:8443/x?y"));
    EXPECT(req_parse_url("https://H:443/", &u) == 0);
    EXPECT(req_format_url(&u, buf, sizeof(buf)) == 0 && !strcmp(buf, "https://h/"));
    EXPECT(req_format_authority(&u, buf, 1) != 0);
}

static void test_origin(void) {
    req_url a, b;
    EXPECT(req_parse_url("http://h/x", &a) == 0);
    EXPECT(req_parse_url("http://H:80/y", &b) == 0);
    EXPECT(req_same_origin(&a, &b));
    EXPECT(req_parse_url("https://h/x", &b) == 0);
    EXPECT(!req_same_origin(&a, &b));
    EXPECT(req_parse_url("http://h:81/x", &b) == 0);
    EXPECT(!req_same_origin(&a, &b));
    EXPECT(req_parse_url("http://h.evil/x", &b) == 0);
    EXPECT(!req_same_origin(&a, &b));
}

static void test_resolve(void) {
    /* RFC 3986 section 5.4 */
    static const struct {
        const char *ref, *want;
    } cases[] = {
        {"g", "http://a/b/c/g"},          {"./g", "http://a/b/c/g"},
        {"g/", "http://a/b/c/g/"},        {"/g", "http://a/g"},
        {"//g", "http://g/"},              {"?y", "http://a/b/c/d;p?y"},
        {"g?y", "http://a/b/c/g?y"},      {"#s", "http://a/b/c/d;p?q"},
        {"g#s", "http://a/b/c/g"},        {"g?y#s", "http://a/b/c/g?y"},
        {";x", "http://a/b/c/;x"},        {"g;x", "http://a/b/c/g;x"},
        {"", "http://a/b/c/d;p?q"},       {".", "http://a/b/c/"},
        {"./", "http://a/b/c/"},          {"..", "http://a/b/"},
        {"../", "http://a/b/"},           {"../g", "http://a/b/g"},
        {"../..", "http://a/"},           {"../../", "http://a/"},
        {"../../g", "http://a/g"},        {"../../../g", "http://a/g"},
        {"../../../../g", "http://a/g"},  {"/./g", "http://a/g"},
        {"/../g", "http://a/g"},          {"g.", "http://a/b/c/g."},
        {".g", "http://a/b/c/.g"},        {"g..", "http://a/b/c/g.."},
        {"..g", "http://a/b/c/..g"},      {"./../g", "http://a/b/g"},
        {"./g/.", "http://a/b/c/g/"},     {"g/./h", "http://a/b/c/g/h"},
        {"g/../h", "http://a/b/c/h"},     {"g;x=1/./y", "http://a/b/c/g;x=1/y"},
        {"g;x=1/../y", "http://a/b/c/y"}, {"g?y/./x", "http://a/b/c/g?y/./x"},
        {"https://x/y", "https://x/y"},   {"HTTP://X", "http://x/"},
        {"//g/../x", "http://g/x"},       {"http://h/a/./b/../c?q/../", "http://h/a/c?q/../"},
        {"//.2/..//.]/", "http://.2//.]/"},
    };
    req_url base;
    size_t i;
    char out[REQ_URL_MAX];
    EXPECT(req_parse_url("http://a/b/c/d;p?q", &base) == 0);
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int rc = req_resolve_ref(&base, cases[i].ref, out, sizeof(out));
        if (!cases[i].want) {
            EXPECT_MSG(rc != 0, "resolve '%s' should fail", cases[i].ref);
            continue;
        }
        EXPECT_MSG(rc == 0 && !strcmp(out, cases[i].want), "resolve '%s' -> '%s' (want '%s')",
                   cases[i].ref, rc ? "<err>" : out, cases[i].want);
    }
    EXPECT(req_resolve_ref(&base, "ftp://x/", out, sizeof(out)) != 0);
    EXPECT(req_resolve_ref(&base, "javascript:alert(1)", out, sizeof(out)) != 0);
    EXPECT(req_resolve_ref(&base, "g", out, 8) != 0);

    EXPECT(req_parse_url("https://[::1]:8443/a/b", &base) == 0);
    EXPECT(req_resolve_ref(&base, "../c", out, sizeof(out)) == 0 && !strcmp(out, "https://[::1]:8443/c"));
    EXPECT(req_resolve_ref(&base, "//other/x", out, sizeof(out)) == 0 && !strcmp(out, "https://other/x"));
}

/* -------------------------------------------------------------- responses */

typedef struct {
    req_err err;
    int status;
    const char *body;
    int keep_alive;
} parse_res;

typedef struct {
    int fd;
    const char *data;
    size_t n;
} feeder;

/* Writes the input from another thread: socket buffers can be smaller than the input
 * (AF_UNIX on macOS defaults to 8 KiB), so writing it all up front would block. */
static void *feed(void *arg) {
    feeder *f = (feeder *)arg;
    size_t off = 0;
    while (off < f->n) {
        ssize_t w = send(f->fd, f->data + off, f->n - off, REQ_SEND_FLAGS);
        if (w <= 0) break;
        off += (size_t)w;
    }
    shutdown(f->fd, SHUT_WR);
    return NULL;
}

static parse_res parse_bytes(const char *data, size_t n, const char *method, size_t max_body) {
    int sv[2];
    req_conn cn;
    req_rd *rd;
    req_buf h, b;
    parse_res pr;
    static char bodycopy[1024];
    feeder f;
    pthread_t th;
    memset(&pr, 0, sizeof(pr));
    memset(&h, 0, sizeof(h));
    memset(&b, 0, sizeof(b));
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        pr.err = REQ_ERR_IO;
        return pr;
    }
#ifdef SO_NOSIGPIPE
    {
        int one = 1; /* the parser may stop early and close its end */
        setsockopt(sv[1], SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
    }
#endif
    f.fd = sv[1];
    f.data = data;
    f.n = n;
    if (pthread_create(&th, NULL, feed, &f) != 0) {
        close(sv[0]);
        close(sv[1]);
        pr.err = REQ_ERR_IO;
        return pr;
    }
    memset(&cn, 0, sizeof(cn));
    cn.fd = sv[0];
    rd = (req_rd *)calloc(1, sizeof(*rd));
    rd->cn = &cn;
    rd->deadline = req_now_ms() + 2000;
    if (!pr.err) pr.err = req_read_response(rd, method, max_body, &h, &b, &pr.status, &pr.keep_alive);
    if (!pr.err && b.p && b.p[b.len] != '\0') pr.err = REQ_ERR_PARSE; /* body must be NUL-terminated */
    snprintf(bodycopy, sizeof(bodycopy), "%.*s", (int)b.len, b.p ? b.p : "");
    pr.body = bodycopy;
    close(sv[0]); /* unblocks the feeder if the parser stopped early */
    pthread_join(th, NULL);
    free(rd);
    req_buf_free(&h);
    req_buf_free(&b);
    close(sv[1]);
    return pr;
}

static void test_responses(void) {
    static const struct {
        const char *name, *in, *method;
        req_err err;
        int status;
        const char *body;
        int ka;
    } cases[] = {
        {"content-length", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", "GET", REQ_OK, 200, "hello", 1},
        {"no reason phrase", "HTTP/1.1 200\r\nContent-Length: 2\r\n\r\nok", "GET", REQ_OK, 200, "ok", 1},
        {"bare LF", "HTTP/1.1 200 OK\nContent-Length: 2\n\nok", "GET", REQ_OK, 200, "ok", 1},
        {"zero length + junk", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nhello", "GET", REQ_OK, 200, "", 0},
        {"head ignores length", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", "HEAD", REQ_OK, 200, "", 1},
        {"chunked + ext + trailer",
         "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;x=y\r\nhello\r\n6 \r\n world\r\n0\r\nT: v\r\n\r\n",
         "GET", REQ_OK, 200, "hello world", 1},
        {"chunked uppercase", "HTTP/1.1 200 OK\r\nTransfer-Encoding: CHUNKED\r\n\r\nA\r\n0123456789\r\n0\r\n\r\n",
         "GET", REQ_OK, 200, "0123456789", 1},
        {"1xx skipped",
         "HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 100 Continue\r\n\r\n"
         "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nREAL",
         "GET", REQ_OK, 200, "REAL", 1},
        {"close-delimited", "HTTP/1.1 200 OK\r\n\r\nuntil close", "GET", REQ_OK, 200, "until close", 0},
        {"http/1.0 default close", "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok", "GET", REQ_OK, 200, "ok", 0},
        {"http/1.0 keep-alive", "HTTP/1.0 200 OK\r\nConnection: Keep-Alive\r\nContent-Length: 2\r\n\r\nok", "GET",
         REQ_OK, 200, "ok", 1},
        {"connection close list", "HTTP/1.1 200 OK\r\nConnection: foo, close\r\nContent-Length: 2\r\n\r\nok",
         "GET", REQ_OK, 200, "ok", 0},
        {"same CL list", "HTTP/1.1 200 OK\r\nContent-Length: 2, 2\r\nContent-Length: 2\r\n\r\nok", "GET", REQ_OK,
         200, "ok", 1},
        {"204 no body", "HTTP/1.1 204 No Content\r\n\r\n", "GET", REQ_OK, 204, "", 1},
        {"304 ignores CL", "HTTP/1.1 304 Not Modified\r\nContent-Length: 100\r\n\r\n", "GET", REQ_OK, 304, "", 1},
        {"101 not reused", "HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\n\r\n", "GET", REQ_OK, 101, "", 0},
        {"TE+CL: chunked wins, no reuse",
         "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n", "GET",
         REQ_OK, 200, "ok", 0},
        {"TE gzip only: until close", "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nraw", "GET", REQ_OK, 200,
         "raw", 0},
        {"TE gzip, chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
         "GET", REQ_OK, 200, "abc", 1},
        {"stray bytes after message", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokGARBAGE", "GET", REQ_OK, 200,
         "ok", 0},
        {"conflicting CL", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!", "GET",
         REQ_ERR_PARSE, 0, NULL, 0},
        {"CL junk", "HTTP/1.1 200 OK\r\nContent-Length: 5abc\r\n\r\nhello", "GET", REQ_ERR_PARSE, 0, NULL, 0},
        {"CL negative", "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n", "GET", REQ_ERR_PARSE, 0, NULL, 0},
        {"CL huge", "HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999\r\n\r\n", "GET", REQ_ERR_PARSE, 0,
         NULL, 0},
        {"obs-fold", "HTTP/1.1 200 OK\r\nX: a\r\n b\r\nContent-Length: 0\r\n\r\n", "GET", REQ_ERR_PARSE, 0, NULL,
         0},
        {"space before colon", "HTTP/1.1 200 OK\r\nContent-Length : 0\r\n\r\n", "GET", REQ_ERR_PARSE, 0, NULL, 0},
        {"no colon", "HTTP/1.1 200 OK\r\nbogus\r\n\r\n", "GET", REQ_ERR_PARSE, 0, NULL, 0},
        {"bare CR", "HTTP/1.1 200 OK\r\nX: a\rb\r\nContent-Length: 0\r\n\r\n", "GET", REQ_ERR_PARSE, 0, NULL, 0},
        {"truncated CL body", "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc", "GET", REQ_ERR_PARSE, 0, NULL, 0},
        {"truncated chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel", "GET",
         REQ_ERR_PARSE, 0, NULL, 0},
        {"chunked missing CRLF", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nokXX0\r\n\r\n", "GET",
         REQ_ERR_PARSE, 0, NULL, 0},
        {"bad chunk size", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n", "GET", REQ_ERR_PARSE, 0,
         NULL, 0},
        {"chunk size junk", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5x\r\nhello\r\n0\r\n\r\n",
         "GET", REQ_ERR_PARSE, 0, NULL, 0},
        {"chunk size overflow", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffffff\r\n",
         "GET", REQ_ERR_OVERFLOW, 0, NULL, 0},
        {"body over limit", "HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\n", "GET", REQ_ERR_OVERFLOW, 0, NULL, 0},
        {"chunks over limit",
         "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\n0123456789abcdef\r\n10\r\n0123456789abcdef\r\n0\r\n\r\n",
         "GET", REQ_ERR_OVERFLOW, 0, NULL, 0},
        {"status 4 digits", "HTTP/1.1 2000 OK\r\n\r\n", "GET", REQ_ERR_PARSE, 0, NULL, 0},
        {"status out of range", "HTTP/1.1 600 X\r\n\r\n", "GET", REQ_ERR_PARSE, 0, NULL, 0},
        {"http/2 status line", "HTTP/2 200\r\n\r\n", "GET", REQ_ERR_PARSE, 0, NULL, 0},
        {"not http", "ICY 200 OK\r\n\r\n", "GET", REQ_ERR_PARSE, 0, NULL, 0},
        {"empty", "", "GET", REQ_ERR_CLOSED, 0, NULL, 0},
        {"eof in headers", "HTTP/1.1 200 OK\r\nX: y\r\n", "GET", REQ_ERR_PARSE, 0, NULL, 0},
    };
    size_t i;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        parse_res pr = parse_bytes(cases[i].in, strlen(cases[i].in), cases[i].method, 24);
        EXPECT_MSG(pr.err == cases[i].err, "%s: err=%s want %s", cases[i].name, req_err_str(pr.err),
                   req_err_str(cases[i].err));
        if (pr.err || cases[i].err) continue;
        EXPECT_MSG(pr.status == cases[i].status, "%s: status=%d", cases[i].name, pr.status);
        EXPECT_MSG(!strcmp(pr.body, cases[i].body), "%s: body=[%s]", cases[i].name, pr.body);
        EXPECT_MSG(pr.keep_alive == cases[i].ka, "%s: keep_alive=%d", cases[i].name, pr.keep_alive);
    }
}

static void test_response_limits(void) {
    char *big;
    size_t n = 0, i;
    parse_res pr;
    /* header block above 64 KiB */
    big = (char *)malloc(80 * 1024);
    n += (size_t)sprintf(big, "HTTP/1.1 200 OK\r\n");
    for (i = 0; i < 1000; i++) n += (size_t)sprintf(big + n, "X-Pad-%04zu: %060d\r\n", i, 0);
    n += (size_t)sprintf(big + n, "\r\n");
    pr = parse_bytes(big, n, "GET", 1024);
    EXPECT(pr.err == REQ_ERR_OVERFLOW);

    /* one header line longer than the line buffer */
    n = (size_t)sprintf(big, "HTTP/1.1 200 OK\r\nX: ");
    memset(big + n, 'a', REQ_LINE_MAX + 10);
    n += REQ_LINE_MAX + 10;
    n += (size_t)sprintf(big + n, "\r\n\r\n");
    pr = parse_bytes(big, n, "GET", 1024);
    EXPECT(pr.err == REQ_ERR_OVERFLOW);

    /* endless 1xx */
    n = 0;
    for (i = 0; i < REQ_INFO_MAX + 2; i++) n += (size_t)sprintf(big + n, "HTTP/1.1 100 Continue\r\n\r\n");
    n += (size_t)sprintf(big + n, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    pr = parse_bytes(big, n, "GET", 1024);
    EXPECT(pr.err == REQ_ERR_PARSE);
    free(big);
}

static void test_header_api(void) {
    req_response r;
    size_t n = 0;
    const char *v;
    char hdrs[] = "HTTP/1.1 200 OK: not-a-header\r\nx-a:   v1  \r\nX-B:\r\nX-A: second\r\n\r\n";
    memset(&r, 0, sizeof(r));
    r.headers = hdrs;
    r.headers_len = strlen(hdrs);
    v = req_header_find(&r, "X-A", &n);
    EXPECT(v && n == 2 && !memcmp(v, "v1", 2));
    v = req_header_find(&r, "x-b", &n);
    EXPECT(v && n == 0);
    EXPECT(req_header_find(&r, "HTTP/1.1 200 OK", &n) == NULL); /* status line is not a field */
    EXPECT(req_header_find(&r, "X-C", &n) == NULL);
    EXPECT(req_header_get(&r, "x-a") == req_header_find(&r, "X-A", NULL));
    EXPECT(req_header_get(NULL, "x") == NULL);
}

static void test_misc(void) {
    EXPECT(req_is_token("GET", 3));
    EXPECT(!req_is_token("G T", 3));
    EXPECT(!req_is_token("", 0));
    EXPECT(strcmp(req_err_str(REQ_ERR_TLS_VERIFY), "unknown") != 0);
    EXPECT(strcmp(req_err_str(REQ_ERR_REDIRECTS), "unknown") != 0);
    EXPECT(strcmp(req_err_str((req_err)99), "unknown") == 0);
}

int main(void) {
    test_parse_ok();
    test_parse_bad();
    test_format();
    test_origin();
    test_resolve();
    test_responses();
    test_response_limits();
    test_header_api();
    test_misc();
    if (g_fail) {
        fprintf(stderr, "unit: %d/%d failed\n", g_fail, g_run);
        return 1;
    }
    printf("unit: %d checks ok\n", g_run);
    return 0;
}
