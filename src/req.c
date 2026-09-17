#include "req_internal.h"

static req_response req_fail(req_err e) {
    req_response r;
    memset(&r, 0, sizeof(r));
    r.err = e;
    return r;
}

const char *req_version(void) { return REQ_VERSION; }

const char *req_err_str(req_err e) {
    switch (e) {
    case REQ_OK: return "ok";
    case REQ_ERR_URL: return "invalid url";
    case REQ_ERR_DNS: return "dns";
    case REQ_ERR_CONNECT: return "connect";
    case REQ_ERR_TLS: return "tls";
    case REQ_ERR_TIMEOUT: return "timeout";
    case REQ_ERR_IO: return "io";
    case REQ_ERR_PARSE: return "parse";
    case REQ_ERR_OVERFLOW: return "overflow";
    case REQ_ERR_REJECT: return "rejected";
    case REQ_ERR_OOM: return "out of memory";
    case REQ_ERR_CLOSED: return "connection closed";
    default: return "unknown";
    }
}

void req_response_free(req_response *r) {
    if (!r) return;
    free(r->body);
    free(r->headers);
    r->body = r->headers = NULL;
    r->body_len = r->headers_len = 0;
}

req_client *req_client_new(void) {
    req_client *c = (req_client *)calloc(1, sizeof(*c));
    int i;
    if (!c) return NULL;
    c->connect_ms = 10000;
    c->io_ms = 30000;
    c->retries = 2;
    c->redirects = 5;
    c->max_body = REQ_BODY_DEFAULT;
    for (i = 0; i < REQ_POOL_MAX; i++) c->pool[i].fd = -1;
#ifdef REQ_USE_OPENSSL
    c->ctx = SSL_CTX_new(TLS_client_method());
    if (!c->ctx) {
        free(c);
        return NULL;
    }
    SSL_CTX_set_default_verify_paths(c->ctx);
    SSL_CTX_set_verify(c->ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_min_proto_version(c->ctx, TLS1_2_VERSION);
#endif
    return c;
}

void req_client_free(req_client *c) {
    int i;
    if (!c) return;
    for (i = 0; i < REQ_POOL_MAX; i++) req_conn_close(&c->pool[i]);
#ifdef REQ_USE_OPENSSL
    SSL_CTX_free(c->ctx);
#endif
    free(c);
}

void req_set_timeout_ms(req_client *c, int connect_ms, int io_ms) {
    if (!c) return;
    if (connect_ms > 0) c->connect_ms = connect_ms;
    if (io_ms > 0) c->io_ms = io_ms;
}

void req_set_retries(req_client *c, int retries) {
    if (c && retries >= 0) c->retries = retries;
}

void req_set_max_body(req_client *c, size_t bytes) {
    if (c && bytes) c->max_body = bytes;
}

void req_set_insecure(req_client *c, int insecure) {
    if (c) c->insecure = insecure ? 1 : 0;
}

void req_set_redirects(req_client *c, int max) {
    if (c && max >= 0) c->redirects = max;
}

static int req_ascii_ieq(const char *a, const char *b, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        unsigned char ca = (unsigned char)a[i], cb = (unsigned char)b[i];
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb - 'A' + 'a');
        if (ca != cb) return 0;
    }
    return 1;
}

const char *req_header_get(const req_response *r, const char *name) {
    const char *p, *end;
    size_t nlen;
    if (!r || !r->headers || !name) return NULL;
    nlen = strlen(name);
    p = r->headers;
    end = r->headers + r->headers_len;
    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        const char *line_end = nl ? nl : end;
        const char *colon = memchr(p, ':', (size_t)(line_end - p));
        if (colon && (size_t)(colon - p) == nlen && req_ascii_ieq(p, name, nlen)) {
            const char *v = colon + 1;
            while (v < line_end && (*v == ' ' || *v == '\t')) v++;
            return v;
        }
        if (!nl) break;
        p = nl + 1;
    }
    return NULL;
}

static int req_idempotent(const char *m) {
    return !strcmp(m, "GET") || !strcmp(m, "HEAD") || !strcmp(m, "PUT") ||
           !strcmp(m, "DELETE") || !strcmp(m, "OPTIONS");
}

static req_conn *req_pool_take(req_client *c, const req_url *u) {
    int i;
    for (i = 0; i < REQ_POOL_MAX; i++) {
        req_conn *cn = &c->pool[i];
        if (cn->fd >= 0 && !cn->in_use && cn->tls == u->tls && cn->port == u->port &&
            strcmp(cn->host, u->host) == 0) {
            cn->in_use = 1;
            return cn;
        }
    }
    return NULL;
}

static req_conn *req_pool_slot(req_client *c) {
    int i;
    for (i = 0; i < REQ_POOL_MAX; i++) {
        if (c->pool[i].fd < 0) return &c->pool[i];
    }
    for (i = 0; i < REQ_POOL_MAX; i++) {
        if (!c->pool[i].in_use) {
            req_conn_close(&c->pool[i]);
            return &c->pool[i];
        }
    }
    return NULL;
}

static void req_pool_release(req_conn *cn, int keep) {
    if (!cn) return;
    if (!keep) {
        req_conn_close(cn);
        return;
    }
    cn->in_use = 0;
}

typedef struct {
    req_conn *cn;
    int64_t deadline;
    char tmp[4096];
    size_t tlen;
    size_t toff;
} req_rd;

static req_err req_rd_fill(req_rd *rd) {
    int n;
    if (rd->toff < rd->tlen) return 0;
    rd->toff = rd->tlen = 0;
    n = req_io_read(rd->cn, rd->tmp, (int)sizeof(rd->tmp), rd->deadline);
    if (n == -2) return REQ_ERR_TIMEOUT;
    if (n < 0) return REQ_ERR_IO;
    if (n == 0) return REQ_ERR_CLOSED;
    rd->tlen = (size_t)n;
    return REQ_OK;
}

static req_err req_rd_get(req_rd *rd, char *out, size_t want, size_t *got) {
    size_t n;
    req_err e = req_rd_fill(rd);
    if (e) return e;
    n = rd->tlen - rd->toff;
    if (n > want) n = want;
    memcpy(out, rd->tmp + rd->toff, n);
    rd->toff += n;
    *got = n;
    return REQ_OK;
}

static req_err req_rd_line(req_rd *rd, char *line, size_t cap, size_t *out_len) {
    size_t len = 0;
    for (;;) {
        char ch;
        size_t g = 0;
        req_err e = req_rd_get(rd, &ch, 1, &g);
        if (e) return e;
        if (ch == '\n') {
            if (len > 0 && line[len - 1] == '\r') len--;
            line[len] = '\0';
            *out_len = len;
            return REQ_OK;
        }
        if (len + 1 >= cap) return REQ_ERR_OVERFLOW;
        line[len++] = ch;
    }
}

static req_err req_read_n(req_rd *rd, req_buf *b, size_t n, size_t max_body) {
    while (n) {
        char tmp[4096];
        size_t want = n > sizeof(tmp) ? sizeof(tmp) : n;
        size_t g = 0;
        req_err e = req_rd_get(rd, tmp, want, &g);
        if (e) return e;
        if (b->len + g > max_body) return REQ_ERR_OVERFLOW;
        if (req_buf_append(b, tmp, g)) return REQ_ERR_OOM;
        n -= g;
    }
    return REQ_OK;
}

static int req_hdr_lookup(const char *hdrs, size_t hlen, const char *name, char *out, size_t outsz) {
    req_response tmp;
    const char *v, *e;
    size_t n;
    tmp.headers = (char *)hdrs;
    tmp.headers_len = hlen;
    v = req_header_get(&tmp, name);
    if (!v) return 0;
    e = v;
    while (*e && *e != '\r' && *e != '\n') e++;
    n = (size_t)(e - v);
    while (n && (v[n - 1] == ' ' || v[n - 1] == '\t')) n--;
    if (n + 1u > outsz) return -1;
    memcpy(out, v, n);
    out[n] = '\0';
    return 1;
}

static int req_build_request(req_buf *b, const char *method, const req_url *u, const req_request *r) {
    char lenbuf[32];
    int i;
    char hostport[16];
    if (req_buf_append(b, method, strlen(method)) || req_buf_append(b, " ", 1) ||
        req_buf_append(b, u->path, strlen(u->path)) ||
        req_buf_append(b, " HTTP/1.1\r\nHost: ", strlen(" HTTP/1.1\r\nHost: ")) ||
        req_buf_append(b, u->host, strlen(u->host)))
        return -1;
    if (!((u->tls && u->port == 443) || (!u->tls && u->port == 80))) {
        snprintf(hostport, sizeof(hostport), ":%d", u->port);
        if (req_buf_append(b, hostport, strlen(hostport))) return -1;
    }
    if (req_buf_append(b, "\r\nUser-Agent: libreq/", strlen("\r\nUser-Agent: libreq/")) ||
        req_buf_append(b, REQ_VERSION, strlen(REQ_VERSION)) ||
        req_buf_append(b, "\r\nAccept: */*\r\nConnection: keep-alive\r\n",
                       strlen("\r\nAccept: */*\r\nConnection: keep-alive\r\n")))
        return -1;
    if (r->body_len) {
        if (r->content_type) {
            if (req_has_crlf(r->content_type, strlen(r->content_type))) return -2;
            if (req_buf_append(b, "Content-Type: ", strlen("Content-Type: ")) ||
                req_buf_append(b, r->content_type, strlen(r->content_type)) ||
                req_buf_append(b, "\r\n", 2))
                return -1;
        }
        snprintf(lenbuf, sizeof(lenbuf), "%zu", r->body_len);
        if (req_buf_append(b, "Content-Length: ", strlen("Content-Length: ")) ||
            req_buf_append(b, lenbuf, strlen(lenbuf)) || req_buf_append(b, "\r\n", 2))
            return -1;
    } else if (r->method && (!strcmp(r->method, "POST") || !strcmp(r->method, "PUT") ||
                             !strcmp(r->method, "PATCH"))) {
        if (req_buf_append(b, "Content-Length: 0\r\n", strlen("Content-Length: 0\r\n"))) return -1;
    }
    if (r->headers) {
        for (i = 0; r->headers[i]; i++) {
            size_t n = strlen(r->headers[i]);
            if (req_has_crlf(r->headers[i], n)) return -2;
            if (req_buf_append(b, r->headers[i], n) || req_buf_append(b, "\r\n", 2)) return -1;
        }
    }
    return req_buf_append(b, "\r\n", 2) ||
           (r->body_len && r->body ? req_buf_append(b, r->body, r->body_len) : 0);
}

static req_err req_read_headers(req_rd *rd, req_buf *h) {
    for (;;) {
        char line[REQ_LINE_MAX];
        size_t ln = 0;
        req_err e = req_rd_line(rd, line, sizeof(line), &ln);
        if (e) return e;
        if (req_buf_append(h, line, ln) || req_buf_append(h, "\r\n", 2)) return REQ_ERR_OOM;
        if (h->len > REQ_HDR_MAX) return REQ_ERR_OVERFLOW;
        if (ln == 0) return REQ_OK;
    }
}

static int req_parse_status(const char *headers, int *status) {
    const char *p = headers;
    if (strncmp(p, "HTTP/1.", 7) != 0) return -1;
    p = strchr(p, ' ');
    if (!p) return -1;
    *status = atoi(p + 1);
    if (*status < 100 || *status > 599) return -1;
    return 0;
}

static req_err req_read_chunked(req_rd *rd, req_buf *body, size_t max_body) {
    for (;;) {
        char line[REQ_LINE_MAX];
        size_t ln = 0;
        unsigned long sz;
        char *ep = NULL;
        req_err e = req_rd_line(rd, line, sizeof(line), &ln);
        if (e) return e;
        sz = strtoul(line, &ep, 16);
        if (ep == line) return REQ_ERR_PARSE;
        if (sz == 0) {
            do {
                e = req_rd_line(rd, line, sizeof(line), &ln);
                if (e) return e;
            } while (ln != 0);
            return REQ_OK;
        }
        if ((size_t)sz > max_body || body->len + (size_t)sz > max_body) return REQ_ERR_OVERFLOW;
        e = req_read_n(rd, body, (size_t)sz, max_body);
        if (e) return e;
        e = req_rd_line(rd, line, sizeof(line), &ln);
        if (e) return e;
        if (ln != 0) return REQ_ERR_PARSE;
    }
}

static int req_no_body(int status, const char *method) {
    if (!strcmp(method, "HEAD")) return 1;
    if (status == 204 || status == 304) return 1;
    if (status >= 100 && status < 200) return 1;
    return 0;
}

static int req_join_location(const req_url *base, const char *loc, char *out, size_t outsz) {
    if (!loc || !*loc) return -1;
    if (!strncmp(loc, "http://", 7) || !strncmp(loc, "https://", 8)) {
        if (strlen(loc) + 1 >= outsz) return -1;
        memcpy(out, loc, strlen(loc) + 1);
        return 0;
    }
    if (loc[0] == '/') {
        int n = snprintf(out, outsz, "%s://%s:%d%s", base->tls ? "https" : "http", base->host, base->port, loc);
        return (n < 0 || (size_t)n >= outsz) ? -1 : 0;
    }
    return -1;
}

static req_err req_once(req_client *c, const req_request *r, const char *method, const req_url *u,
                    req_response *out, int *keep_alive) {
    req_conn *cn = NULL, owned;
    req_buf reqb, hdrs, body;
    req_rd rd;
    req_err e;
    int status = 0, pooled = 0;
    char te[64], cl[32], conn[32];
    int64_t deadline;
    memset(&owned, 0, sizeof(owned));
    owned.fd = -1;
    memset(&reqb, 0, sizeof(reqb));
    memset(&hdrs, 0, sizeof(hdrs));
    memset(&body, 0, sizeof(body));
    *keep_alive = 0;

    int br = req_build_request(&reqb, method, u, r);
    if (br == -2) {
        req_buf_free(&reqb);
        return REQ_ERR_REJECT;
    }
    if (br) {
        req_buf_free(&reqb);
        return REQ_ERR_OOM;
    }

    deadline = req_now_ms() + c->connect_ms + c->io_ms;
    cn = req_pool_take(c, u);
    if (cn) pooled = 1;
    else {
        cn = req_pool_slot(c);
        if (!cn) cn = &owned;
        e = req_connect_host(c, cn, u, req_now_ms() + c->connect_ms);
        if (e) {
            req_buf_free(&reqb);
            return e;
        }
    }

    deadline = req_now_ms() + c->io_ms;
    e = req_io_write_all(cn, reqb.p, reqb.len, deadline);
    req_buf_free(&reqb);
    if (e) {
        req_conn_close(cn);
        return e == REQ_ERR_TIMEOUT ? REQ_ERR_TIMEOUT : REQ_ERR_CLOSED;
    }

    memset(&rd, 0, sizeof(rd));
    rd.cn = cn;
    rd.deadline = deadline;
    e = req_read_headers(&rd, &hdrs);
    if (e) {
        req_conn_close(cn);
        req_buf_free(&hdrs);
        return e;
    }
    if (req_parse_status(hdrs.p, &status)) {
        req_conn_close(cn);
        req_buf_free(&hdrs);
        return REQ_ERR_PARSE;
    }

    te[0] = cl[0] = conn[0] = '\0';
    req_hdr_lookup(hdrs.p, hdrs.len, "Transfer-Encoding", te, sizeof(te));
    req_hdr_lookup(hdrs.p, hdrs.len, "Content-Length", cl, sizeof(cl));
    req_hdr_lookup(hdrs.p, hdrs.len, "Connection", conn, sizeof(conn));

    if (!req_no_body(status, method)) {
        if (te[0] && strlen(te) == 7 && req_ascii_ieq(te, "chunked", 7)) {
            e = req_read_chunked(&rd, &body, c->max_body);
        } else if (cl[0]) {
            unsigned long long n = strtoull(cl, NULL, 10);
            if (n > c->max_body || n > SIZE_MAX) e = REQ_ERR_OVERFLOW;
            else e = req_read_n(&rd, &body, (size_t)n, c->max_body);
        } else if (conn[0] && req_ascii_ieq(conn, "close", 5)) {
            for (;;) {
                char tmp[4096];
                size_t g = 0;
                req_err re = req_rd_get(&rd, tmp, sizeof(tmp), &g);
                if (re == REQ_ERR_CLOSED) break;
                if (re) {
                    e = re;
                    break;
                }
                if (body.len + g > c->max_body) {
                    e = REQ_ERR_OVERFLOW;
                    break;
                }
                if (req_buf_append(&body, tmp, g)) {
                    e = REQ_ERR_OOM;
                    break;
                }
            }
        }
        /* HTTP/1.1 keep-alive without length: empty body */
    }

    if (e) {
        req_conn_close(cn);
        req_buf_free(&hdrs);
        req_buf_free(&body);
        return e;
    }

    out->status = status;
    out->headers = hdrs.p;
    out->headers_len = hdrs.len;
    hdrs.p = NULL;
    out->body = body.p ? body.p : (char *)calloc(1, 1);
    out->body_len = body.len;
    body.p = NULL;
    out->err = REQ_OK;
    *keep_alive = !(conn[0] && req_ascii_ieq(conn, "close", 5));
    if (cn == &owned) {
        if (*keep_alive) {
            req_conn *slot = req_pool_slot(c);
            if (slot) *slot = owned;
            else req_conn_close(&owned);
        } else {
            req_conn_close(&owned);
        }
    } else {
        req_pool_release(cn, *keep_alive);
    }
    (void)pooled;
    return REQ_OK;
}

static req_response req_send_url(req_client *c, req_request req, const char *url) {
    req_url u;
    req_response r;
    const char *method;
    int attempt, max_try, redir;
    char urlbuf[4096];
    char loc[2048];

    memset(&r, 0, sizeof(r));
    if (!c || !url) return req_fail(REQ_ERR_URL);
    snprintf(urlbuf, sizeof(urlbuf), "%s", url);
    method = req.method && req.method[0] ? req.method : "GET";
    if (req_has_crlf(method, strlen(method))) return req_fail(REQ_ERR_REJECT);
    req.method = method;
    req.url = urlbuf;

    max_try = req_idempotent(method) ? c->retries + 1 : 1;
    if (max_try < 1) max_try = 1;

    for (redir = 0; redir <= c->redirects; redir++) {
        req_err last = REQ_ERR_IO;
        if (req_parse_url(urlbuf, &u)) return req_fail(REQ_ERR_URL);
#ifndef REQ_USE_OPENSSL
        if (u.tls) return req_fail(REQ_ERR_TLS);
#endif
        for (attempt = 0; attempt < max_try; attempt++) {
            int keep = 0;
            req_response_free(&r);
            memset(&r, 0, sizeof(r));
            last = req_once(c, &req, method, &u, &r, &keep);
            if (last == REQ_OK) break;
            if (last != REQ_ERR_CONNECT && last != REQ_ERR_IO && last != REQ_ERR_TIMEOUT &&
                last != REQ_ERR_CLOSED && last != REQ_ERR_TLS && last != REQ_ERR_DNS)
                return req_fail(last);
        }
        if (last != REQ_OK) return req_fail(last);

        if (r.status >= 300 && r.status < 400 && redir < c->redirects) {
            int f = req_hdr_lookup(r.headers, r.headers_len, "Location", loc, sizeof(loc));
            if (f == 1 && !req_has_crlf(loc, strlen(loc)) &&
                (!strcmp(method, "GET") || !strcmp(method, "HEAD") || r.status == 303)) {
                req_url base = u;
                if (r.status == 303) {
                    method = "GET";
                    req.method = method;
                    req.body = NULL;
                    req.body_len = 0;
                }
                if (req_join_location(&base, loc, urlbuf, sizeof(urlbuf)) == 0) {
                    req_response_free(&r);
                    memset(&r, 0, sizeof(r));
                    continue;
                }
            }
        }
        return r;
    }
    req_response_free(&r);
    return req_fail(REQ_ERR_OVERFLOW);
}

req_response req_send(req_client *c, const req_request *r) {
    req_request tmp;
    if (!r) return req_fail(REQ_ERR_URL);
    tmp = *r;
    return req_send_url(c, tmp, r->url);
}

req_response req_get(req_client *c, const char *url) {
    req_request r;
    memset(&r, 0, sizeof(r));
    r.method = "GET";
    r.url = url;
    return req_send(c, &r);
}

req_response req_head(req_client *c, const char *url) {
    req_request r;
    memset(&r, 0, sizeof(r));
    r.method = "HEAD";
    r.url = url;
    return req_send(c, &r);
}

req_response req_delete(req_client *c, const char *url) {
    req_request r;
    memset(&r, 0, sizeof(r));
    r.method = "DELETE";
    r.url = url;
    return req_send(c, &r);
}

req_response req_post(req_client *c, const char *url, const void *body, size_t len, const char *ct) {
    req_request r;
    memset(&r, 0, sizeof(r));
    r.method = "POST";
    r.url = url;
    r.body = body;
    r.body_len = len;
    r.content_type = ct;
    return req_send(c, &r);
}

req_response req_put(req_client *c, const char *url, const void *body, size_t len, const char *ct) {
    req_request r;
    memset(&r, 0, sizeof(r));
    r.method = "PUT";
    r.url = url;
    r.body = body;
    r.body_len = len;
    r.content_type = ct;
    return req_send(c, &r);
}
