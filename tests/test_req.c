#include "req.h"

#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int g_fail;

static void fail_at(const char *file, int line, const char *msg) {
    fprintf(stderr, "FAIL %s:%d %s\n", file, line, msg);
    g_fail++;
}

#define EXPECT(c)                                                                          \
    do {                                                                                   \
        if (!(c)) fail_at(__FILE__, __LINE__, #c);                                         \
    } while (0)

typedef struct {
    int fd;
    int port;
    volatile int stop;
    pthread_t th;
    int accepts;
} test_srv;

static int srv_read_req(int fd, char *buf, size_t cap, size_t *out) {
    size_t n = 0;
    while (n + 1 < cap) {
        ssize_t r = recv(fd, buf + n, 1, 0);
        if (r <= 0) return -1;
        n += (size_t)r;
        if (n >= 4 && memcmp(buf + n - 4, "\r\n\r\n", 4) == 0) {
            buf[n] = '\0';
            *out = n;
            return 0;
        }
    }
    return -1;
}

static void srv_write_all(int fd, const char *s) {
    size_t n = strlen(s), off = 0;
    while (off < n) {
        ssize_t w = send(fd, s + off, n - off, 0);
        if (w <= 0) return;
        off += (size_t)w;
    }
}

static void srv_handle(int fd, test_srv *s) {
    char req[8192];
    size_t n = 0;
    (void)s;
    for (;;) {
        char resp[2048];
        if (srv_read_req(fd, req, sizeof(req), &n) < 0) return;
        if (strstr(req, "GET /hello")) {
            srv_write_all(fd, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nhello");
        } else if (strstr(req, "HEAD /hello")) {
            srv_write_all(fd, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\n");
        } else if (strstr(req, "GET /chunk")) {
            srv_write_all(fd, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n"
                              "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
        } else if (strstr(req, "POST /echo")) {
            const char *cl = strstr(req, "Content-Length:");
            long blen = cl ? strtol(cl + 15, NULL, 10) : 0;
            char *body = (char *)calloc((size_t)blen + 1u, 1);
            long got = 0;
            while (got < blen) {
                ssize_t r = recv(fd, body + got, (size_t)(blen - got), 0);
                if (r <= 0) {
                    free(body);
                    return;
                }
                got += r;
            }
            snprintf(resp, sizeof(resp),
                     "HTTP/1.1 200 OK\r\nContent-Length: %ld\r\nConnection: keep-alive\r\n\r\n", blen);
            srv_write_all(fd, resp);
            if (blen) send(fd, body, (size_t)blen, 0);
            free(body);
        } else if (strstr(req, "GET /redir")) {
            srv_write_all(fd, "HTTP/1.1 302 Found\r\nLocation: /hello\r\nContent-Length: 0\r\n"
                              "Connection: keep-alive\r\n\r\n");
        } else if (strstr(req, "GET /close")) {
            srv_write_all(fd, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nbye");
            return;
        } else if (strstr(req, "GET /empty")) {
            srv_write_all(fd, "HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n");
        } else {
            srv_write_all(fd, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            return;
        }
        if (strstr(req, "Connection: close")) return;
    }
}

static void *srv_thread(void *arg) {
    test_srv *s = (test_srv *)arg;
    while (!s->stop) {
        struct timeval tv;
        fd_set rfds;
        int cfd;
        FD_ZERO(&rfds);
        FD_SET(s->fd, &rfds);
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        if (select(s->fd + 1, &rfds, NULL, NULL, &tv) <= 0) continue;
        cfd = accept(s->fd, NULL, NULL);
        if (cfd < 0) continue;
        s->accepts++;
        srv_handle(cfd, s);
        close(cfd);
    }
    return NULL;
}

static int srv_start(test_srv *s) {
    struct sockaddr_in addr;
    socklen_t sl = sizeof(addr);
    int one = 1;
    memset(s, 0, sizeof(*s));
    s->fd = (int)socket(AF_INET, SOCK_STREAM, 0);
    if (s->fd < 0) return -1;
    setsockopt(s->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(s->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) return -1;
    if (listen(s->fd, 16) < 0) return -1;
    if (getsockname(s->fd, (struct sockaddr *)&addr, &sl) < 0) return -1;
    s->port = ntohs(addr.sin_port);
    return pthread_create(&s->th, NULL, srv_thread, s);
}

static void srv_stop(test_srv *s) {
    s->stop = 1;
    shutdown(s->fd, SHUT_RDWR);
    pthread_join(s->th, NULL);
    close(s->fd);
}

static void url_on(char *buf, size_t n, int port, const char *path) {
    snprintf(buf, n, "http://127.0.0.1:%d%s", port, path);
}

int main(void) {
    test_srv srv;
    req_client *c;
    req_response r;
    char url[128];
    int a0;

    EXPECT(strcmp(req_version(), "1.0.0") == 0);
    EXPECT(srv_start(&srv) == 0);
    c = req_client_new();
    EXPECT(c != NULL);
    req_set_timeout_ms(c, 2000, 2000);
    req_set_retries(c, 1);

    url_on(url, sizeof(url), srv.port, "/hello");
    r = req_get(c, url);
    EXPECT(r.err == REQ_OK);
    EXPECT(r.status == 200);
    EXPECT(r.body_len == 5 && memcmp(r.body, "hello", 5) == 0);
    EXPECT(req_header_get(&r, "Content-Length") != NULL);
    req_response_free(&r);

    url_on(url, sizeof(url), srv.port, "/hello");
    r = req_head(c, url);
    EXPECT(r.err == REQ_OK && r.status == 200 && r.body_len == 0);
    req_response_free(&r);

    url_on(url, sizeof(url), srv.port, "/chunk");
    r = req_get(c, url);
    EXPECT(r.err == REQ_OK);
    EXPECT(r.body_len == 11 && memcmp(r.body, "hello world", 11) == 0);
    req_response_free(&r);

    url_on(url, sizeof(url), srv.port, "/echo");
    r = req_post(c, url, "xyz", 3, "text/plain");
    EXPECT(r.err == REQ_OK && r.status == 200);
    EXPECT(r.body_len == 3 && memcmp(r.body, "xyz", 3) == 0);
    req_response_free(&r);

    url_on(url, sizeof(url), srv.port, "/redir");
    r = req_get(c, url);
    EXPECT(r.err == REQ_OK && r.status == 200);
    EXPECT(r.body_len == 5 && memcmp(r.body, "hello", 5) == 0);
    req_response_free(&r);

    url_on(url, sizeof(url), srv.port, "/empty");
    r = req_get(c, url);
    EXPECT(r.err == REQ_OK && r.status == 204 && r.body_len == 0);
    req_response_free(&r);

    url_on(url, sizeof(url), srv.port, "/nope");
    r = req_get(c, url);
    EXPECT(r.err == REQ_OK && r.status == 404);
    req_response_free(&r);

    a0 = srv.accepts;
    {
        req_client *c2 = req_client_new();
        req_set_timeout_ms(c2, 2000, 2000);
        url_on(url, sizeof(url), srv.port, "/hello");
        r = req_get(c2, url);
        EXPECT(r.err == REQ_OK);
        req_response_free(&r);
        r = req_get(c2, url);
        EXPECT(r.err == REQ_OK);
        req_response_free(&r);
        EXPECT(srv.accepts == a0 + 1);
        req_client_free(c2);
    }

    url_on(url, sizeof(url), srv.port, "/close");
    r = req_get(c, url);
    EXPECT(r.err == REQ_OK && r.body_len == 3);
    req_response_free(&r);

    r = req_get(c, "http://127.0.0.1/hi\r\nHost: evil");
    EXPECT(r.err == REQ_ERR_URL);
    req_response_free(&r);

    r = req_get(c, "not-a-url");
    EXPECT(r.err == REQ_ERR_URL);
    req_response_free(&r);

    {
        req_request rq;
        const char *hdrs[] = {"X-Test: 1\r\nHost: evil", NULL};
        memset(&rq, 0, sizeof(rq));
        url_on(url, sizeof(url), srv.port, "/hello");
        rq.method = "GET";
        rq.url = url;
        rq.headers = hdrs;
        r = req_send(c, &rq);
        EXPECT(r.err == REQ_ERR_REJECT);
        req_response_free(&r);
    }

    req_client_free(c);
    srv_stop(&srv);

    if (g_fail) {
        fprintf(stderr, "%d failed\n", g_fail);
        return 1;
    }
    puts("ok");
    return 0;
}
