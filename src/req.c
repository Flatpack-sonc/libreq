#include "req_internal.h"

#define REQ_INLINE_BODY (16u * 1024u) /* bodies up to this size share the header write */

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
    case REQ_ERR_TLS_VERIFY: return "tls certificate verification failed";
    case REQ_ERR_REDIRECTS: return "too many redirects";
    default: return "unknown";
    }
}

void req_response_free(req_response *r) {
    if (!r) return;
    free(r->body);
    free(r->headers);
    free(r->url);
    r->body = r->headers = r->url = NULL;
    r->body_len = r->headers_len = 0;
}

/* ------------------------------------------------------------------ client */

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
    c->bio_meth = req_bio_method_new();
    if (!c->ctx || !c->bio_meth) {
        SSL_CTX_free(c->ctx);
        if (c->bio_meth) BIO_meth_free(c->bio_meth);
        free(c);
        return NULL;
    }
    SSL_CTX_set_default_verify_paths(c->ctx);
    SSL_CTX_set_verify(c->ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_min_proto_version(c->ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(c->ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);
#ifdef SSL_OP_IGNORE_UNEXPECTED_EOF
    /* Body framing (Content-Length / chunked) already detects truncation. */
    SSL_CTX_set_options(c->ctx, SSL_OP_IGNORE_UNEXPECTED_EOF);
#endif
#endif
    return c;
}

void req_client_free(req_client *c) {
    int i;
    if (!c) return;
    for (i = 0; i < REQ_POOL_MAX; i++) req_conn_close(&c->pool[i]);
#ifdef REQ_USE_OPENSSL
    SSL_CTX_free(c->ctx);
    BIO_meth_free(c->bio_meth);
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

int req_set_ca(req_client *c, const char *ca_file, const char *ca_dir) {
#ifdef REQ_USE_OPENSSL
    X509_STORE *st;
    int i;
    if (!c || (!ca_file && !ca_dir)) return -1;
    st = X509_STORE_new();
    if (!st) return -1;
    SSL_CTX_set_cert_store(c->ctx, st); /* takes ownership, frees the old store */
    if (SSL_CTX_load_verify_locations(c->ctx, ca_file, ca_dir) != 1) {
        ERR_clear_error();
        return -1;
    }
    /* Connections verified against the old trust store must not be reused. */
    for (i = 0; i < REQ_POOL_MAX; i++) {
        if (c->pool[i].tls) req_conn_close(&c->pool[i]);
    }
    return 0;
#else
    (void)c;
    (void)ca_file;
    (void)ca_dir;
    return -1;
#endif
}

/* ----------------------------------------------------------------- headers */

/* Finds the next field named `name` at or after *pos (skipping the status line). */
static const char *req_hdr_next(const char *h, size_t hlen, const char **pos, const char *name,
                                size_t *vlen) {
    const char *p, *end = h + hlen;
    size_t nlen = strlen(name);
    if (!*pos) {
        const char *nl = memchr(h, '\n', hlen);
        if (!nl) return NULL;
        *pos = nl + 1;
    }
    p = *pos;
    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        const char *le = nl ? nl : end;
        const char *colon = memchr(p, ':', (size_t)(le - p));
        *pos = nl ? nl + 1 : end;
        if (colon && (size_t)(colon - p) == nlen && req_ascii_ieq(p, name, nlen)) {
            const char *v = colon + 1, *ve = le;
            if (ve > v && ve[-1] == '\r') ve--;
            while (v < ve && (*v == ' ' || *v == '\t')) v++;
            while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t')) ve--;
            *vlen = (size_t)(ve - v);
            return v;
        }
        p = *pos;
    }
    return NULL;
}

const char *req_header_find(const req_response *r, const char *name, size_t *len) {
    const char *pos = NULL;
    size_t n = 0;
    const char *v;
    if (!r || !r->headers || !name) return NULL;
    v = req_hdr_next(r->headers, r->headers_len, &pos, name, &n);
    if (v && len) *len = n;
    return v;
}

const char *req_header_get(const req_response *r, const char *name) {
    return req_header_find(r, name, NULL);
}

/* Calls fn for each comma-separated, whitespace-trimmed element of every `name` field. */
typedef int (*req_list_fn)(const char *s, size_t n, void *ud);

static int req_hdr_each(const req_buf *h, const char *name, req_list_fn fn, void *ud) {
    const char *pos = NULL, *v;
    size_t vl = 0;
    int found = 0;
    while ((v = req_hdr_next(h->p, h->len, &pos, name, &vl)) != NULL) {
        const char *e = v + vl;
        found = 1;
        while (v <= e) {
            const char *comma = memchr(v, ',', (size_t)(e - v));
            const char *ie = comma ? comma : e;
            const char *s = v;
            while (s < ie && (*s == ' ' || *s == '\t')) s++;
            while (ie > s && (ie[-1] == ' ' || ie[-1] == '\t')) ie--;
            if (ie > s && fn(s, (size_t)(ie - s), ud)) return -1;
            if (!comma) break;
            v = comma + 1;
        }
    }
    return found;
}

typedef struct {
    int seen;
    int bad;
    unsigned long long value;
} req_cl_state;

static int req_cl_item(const char *s, size_t n, void *ud) {
    req_cl_state *st = (req_cl_state *)ud;
    unsigned long long v = 0;
    size_t i;
    if (n > 19) return st->bad = 1;
    for (i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return st->bad = 1;
        v = v * 10u + (unsigned)(s[i] - '0');
    }
    if (st->seen && st->value != v) return st->bad = 1; /* conflicting lengths */
    st->seen = 1;
    st->value = v;
    return 0;
}

typedef struct {
    int seen;
    int last_chunked;
} req_te_state;

static int req_te_item(const char *s, size_t n, void *ud) {
    req_te_state *st = (req_te_state *)ud;
    size_t tl = 0;
    while (tl < n && s[tl] != ';' && s[tl] != ' ' && s[tl] != '\t') tl++;
    st->seen = 1;
    st->last_chunked = tl == 7 && req_ascii_ieq(s, "chunked", 7);
    return 0;
}

typedef struct {
    int close;
    int keep_alive;
} req_conn_state;

static int req_conn_item(const char *s, size_t n, void *ud) {
    req_conn_state *st = (req_conn_state *)ud;
    if (n == 5 && req_ascii_ieq(s, "close", 5)) st->close = 1;
    if (n == 10 && req_ascii_ieq(s, "keep-alive", 10)) st->keep_alive = 1;
    return 0;
}

/* ------------------------------------------------------------------- pool */

static req_conn *req_pool_take(req_client *c, const req_url *u) {
    int i;
    for (i = 0; i < REQ_POOL_MAX; i++) {
        req_conn *cn = &c->pool[i];
        if (cn->fd >= 0 && !cn->in_use && cn->tls == u->tls && cn->port == u->port &&
            strcmp(cn->host, u->host) == 0) {
            if (!req_conn_alive(cn)) {
                req_conn_close(cn);
                continue;
            }
            cn->in_use = 1;
            cn->reused = 1;
            return cn;
        }
    }
    return NULL;
}

static req_conn *req_pool_slot(req_client *c) {
    int i, lru = -1;
    for (i = 0; i < REQ_POOL_MAX; i++) {
        if (c->pool[i].fd < 0) return &c->pool[i];
        if (!c->pool[i].in_use && (lru < 0 || c->pool[i].last_used < c->pool[lru].last_used)) lru = i;
    }
    if (lru < 0) return NULL;
    req_conn_close(&c->pool[lru]);
    return &c->pool[lru];
}

static void req_pool_release(req_conn *cn, int keep) {
    if (!keep) {
        req_conn_close(cn);
        return;
    }
    cn->in_use = 0;
    cn->reused = 0;
    cn->last_used = req_now_ms();
}

/* ------------------------------------------------------------ reading */

static req_err req_rd_fill(req_rd *rd) {
    int n;
    if (rd->toff < rd->tlen) return REQ_OK;
    rd->toff = rd->tlen = 0;
    n = req_io_read(rd->cn, rd->tmp, (int)sizeof(rd->tmp), rd->deadline);
    if (n == -2) return REQ_ERR_TIMEOUT;
    if (n < 0) return REQ_ERR_IO;
    if (n == 0) return REQ_ERR_CLOSED;
    rd->tlen = (size_t)n;
    rd->got += (size_t)n;
    return REQ_OK;
}

static req_err req_rd_line(req_rd *rd, char *line, size_t cap, size_t *out_len) {
    size_t len = 0;
    for (;;) {
        const char *s, *nl;
        size_t take;
        req_err e = req_rd_fill(rd);
        if (e) return e;
        s = rd->tmp + rd->toff;
        nl = memchr(s, '\n', rd->tlen - rd->toff);
        take = nl ? (size_t)(nl - s) : rd->tlen - rd->toff;
        if (len + take + 1 > cap) return REQ_ERR_OVERFLOW;
        memcpy(line + len, s, take);
        len += take;
        rd->toff += take;
        if (nl) {
            rd->toff++;
            if (len > 0 && line[len - 1] == '\r') len--;
            line[len] = '\0';
            if (memchr(line, '\0', len) || memchr(line, '\r', len)) return REQ_ERR_PARSE;
            *out_len = len;
            return REQ_OK;
        }
    }
}

static req_err req_read_n(req_rd *rd, req_buf *b, size_t n, size_t max_body) {
    size_t need;
    if (!req_add_ok(b->len, n, &need) || need > max_body) return REQ_ERR_OVERFLOW;
    if (req_buf_grow(b, need + 1)) return REQ_ERR_OOM;
    b->p[b->len] = '\0';
    while (n) {
        size_t avail, g;
        req_err e = req_rd_fill(rd);
        if (e) return e;
        avail = rd->tlen - rd->toff;
        g = avail < n ? avail : n;
        memcpy(b->p + b->len, rd->tmp + rd->toff, g);
        b->len += g;
        b->p[b->len] = '\0';
        rd->toff += g;
        n -= g;
    }
    return REQ_OK;
}

static req_err req_read_to_close(req_rd *rd, req_buf *b, size_t max_body) {
    for (;;) {
        size_t g;
        req_err e = req_rd_fill(rd);
        if (e == REQ_ERR_CLOSED) return REQ_OK;
        if (e) return e;
        g = rd->tlen - rd->toff;
        if (b->len + g > max_body) return REQ_ERR_OVERFLOW;
        if (req_buf_append(b, rd->tmp + rd->toff, g)) return REQ_ERR_OOM;
        rd->toff += g;
    }
}

static int req_hexval(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static req_err req_read_chunked(req_rd *rd, req_buf *body, size_t max_body) {
    for (;;) {
        char line[REQ_LINE_MAX];
        size_t ln = 0, i = 0, trailer = 0;
        unsigned long long sz = 0;
        req_err e = req_rd_line(rd, line, sizeof(line), &ln);
        if (e) return e == REQ_ERR_CLOSED ? REQ_ERR_PARSE : e;
        while (i < ln && req_hexval(line[i]) >= 0) {
            if (i >= 15) return REQ_ERR_OVERFLOW;
            sz = sz * 16u + (unsigned)req_hexval(line[i]);
            i++;
        }
        if (i == 0) return REQ_ERR_PARSE;
        while (i < ln && (line[i] == ' ' || line[i] == '\t')) i++;
        if (i < ln && line[i] != ';') return REQ_ERR_PARSE;
        if (sz == 0) {
            do { /* trailer section */
                e = req_rd_line(rd, line, sizeof(line), &ln);
                if (e) return e == REQ_ERR_CLOSED ? REQ_ERR_PARSE : e;
                trailer += ln + 2;
                if (trailer > REQ_HDR_MAX) return REQ_ERR_OVERFLOW;
            } while (ln != 0);
            return REQ_OK;
        }
        if (sz > max_body) return REQ_ERR_OVERFLOW;
        e = req_read_n(rd, body, (size_t)sz, max_body);
        if (e) return e == REQ_ERR_CLOSED ? REQ_ERR_PARSE : e;
        e = req_rd_line(rd, line, sizeof(line), &ln);
        if (e) return e == REQ_ERR_CLOSED ? REQ_ERR_PARSE : e;
        if (ln != 0) return REQ_ERR_PARSE;
    }
}

/* "HTTP/1.x SP 3DIGIT [SP reason]" */
static int req_parse_status(const char *line, size_t len, int *status, int *minor) {
    if (len < 12 || memcmp(line, "HTTP/1.", 7) != 0) return -1;
    if (line[7] < '0' || line[7] > '9' || line[8] != ' ') return -1;
    if (!isdigit((unsigned char)line[9]) || !isdigit((unsigned char)line[10]) ||
        !isdigit((unsigned char)line[11]))
        return -1;
    if (len > 12 && line[12] != ' ') return -1;
    *minor = line[7] - '0';
    *status = (line[9] - '0') * 100 + (line[10] - '0') * 10 + (line[11] - '0');
    return (*status < 100 || *status > 599) ? -1 : 0;
}

static req_err req_read_head(req_rd *rd, req_buf *h, int *status, int *minor) {
    char line[REQ_LINE_MAX];
    size_t ln = 0;
    int first = 1;
    h->len = 0;
    for (;;) {
        req_err e = req_rd_line(rd, line, sizeof(line), &ln);
        if (e) return (e == REQ_ERR_CLOSED && rd->got > 0 && !first) ? REQ_ERR_PARSE : e;
        if (first) {
            if (req_parse_status(line, ln, status, minor)) return REQ_ERR_PARSE;
            first = 0;
        } else if (ln) {
            const char *colon = memchr(line, ':', ln);
            /* obs-fold and whitespace before the colon are request-smuggling vectors */
            if (line[0] == ' ' || line[0] == '\t') return REQ_ERR_PARSE;
            if (!colon || !req_is_token(line, (size_t)(colon - line))) return REQ_ERR_PARSE;
        }
        if (req_buf_append(h, line, ln) || req_buf_append(h, "\r\n", 2)) return REQ_ERR_OOM;
        if (h->len > REQ_HDR_MAX) return REQ_ERR_OVERFLOW;
        if (ln == 0) return REQ_OK;
    }
}

req_err req_read_response(req_rd *rd, const char *method, size_t max_body, req_buf *hdrs,
                          req_buf *body, int *status, int *keep_alive) {
    req_cl_state cl;
    req_te_state te;
    req_conn_state cs;
    int minor = 1, interim = 0;
    req_err e;
    *keep_alive = 0;

    for (;;) {
        e = req_read_head(rd, hdrs, status, &minor);
        if (e) return e;
        if (*status >= 100 && *status < 200 && *status != 101) {
            if (++interim > REQ_INFO_MAX) return REQ_ERR_PARSE;
            continue; /* 100 Continue, 103 Early Hints, ... */
        }
        break;
    }

    memset(&cl, 0, sizeof(cl));
    memset(&te, 0, sizeof(te));
    memset(&cs, 0, sizeof(cs));
    req_hdr_each(hdrs, "Content-Length", req_cl_item, &cl);
    req_hdr_each(hdrs, "Transfer-Encoding", req_te_item, &te);
    req_hdr_each(hdrs, "Connection", req_conn_item, &cs);
    if (cl.bad && !te.seen) return REQ_ERR_PARSE;

    *keep_alive = minor >= 1 ? !cs.close : (cs.keep_alive && !cs.close);

    if (*status == 101) {
        *keep_alive = 0; /* protocol upgrades are not supported */
        return REQ_OK;
    }
    if (!strcmp(method, "HEAD") || *status == 204 || *status == 304) {
        e = REQ_OK;
    } else if (te.seen) {
        if (cl.seen || cl.bad) *keep_alive = 0; /* RFC 9112 6.3: TE overrides CL; do not reuse */
        if (te.last_chunked && minor >= 1) {
            e = req_read_chunked(rd, body, max_body);
        } else {
            *keep_alive = 0;
            e = req_read_to_close(rd, body, max_body);
        }
    } else if (cl.seen) {
        if (cl.value > (unsigned long long)max_body) return REQ_ERR_OVERFLOW;
        e = req_read_n(rd, body, (size_t)cl.value, max_body);
        if (e == REQ_ERR_CLOSED) e = REQ_ERR_PARSE; /* truncated body */
    } else {
        *keep_alive = 0; /* body is delimited by connection close */
        e = req_read_to_close(rd, body, max_body);
    }
    if (e) return e;
    if (rd->toff < rd->tlen) *keep_alive = 0; /* stray bytes after the message */
    return REQ_OK;
}

/* ------------------------------------------------------------ writing */

static int req_hdr_is(const char *line, size_t name_len, const char *name) {
    return strlen(name) == name_len && req_ascii_ieq(line, name, name_len);
}

static int req_is_credential(const char *line, size_t nl) {
    return req_hdr_is(line, nl, "Authorization") || req_hdr_is(line, nl, "Proxy-Authorization") ||
           req_hdr_is(line, nl, "Cookie") || req_hdr_is(line, nl, "Cookie2");
}

/* 0 ok, -1 oom, -2 rejected */
static int req_build_head(req_buf *b, const char *method, const req_url *u, const req_request *r,
                          int strip_creds, int inline_body) {
    enum { H_HOST = 1, H_UA = 2, H_ACCEPT = 4, H_CONN = 8, H_CTYPE = 16 };
    char tmp[300];
    int have = 0, i;

    if (r->headers) {
        for (i = 0; r->headers[i]; i++) {
            const char *h = r->headers[i];
            size_t n = strlen(h);
            const char *colon = memchr(h, ':', n);
            size_t nl;
            if (req_has_crlf(h, n) || !colon) return -2;
            nl = (size_t)(colon - h);
            if (!req_is_token(h, nl)) return -2;
            if (req_hdr_is(h, nl, "Content-Length") || req_hdr_is(h, nl, "Transfer-Encoding")) return -2;
            if (req_hdr_is(h, nl, "Host")) have |= H_HOST;
            else if (req_hdr_is(h, nl, "User-Agent")) have |= H_UA;
            else if (req_hdr_is(h, nl, "Accept")) have |= H_ACCEPT;
            else if (req_hdr_is(h, nl, "Connection")) have |= H_CONN;
            else if (req_hdr_is(h, nl, "Content-Type")) have |= H_CTYPE;
        }
    }
    if (r->content_type && req_has_crlf(r->content_type, strlen(r->content_type))) return -2;

    if (req_buf_puts(b, method) || req_buf_puts(b, " ") || req_buf_puts(b, u->path) ||
        req_buf_puts(b, " HTTP/1.1\r\n"))
        return -1;
    if (!(have & H_HOST)) {
        if (req_format_authority(u, tmp, sizeof(tmp))) return -1;
        if (req_buf_puts(b, "Host: ") || req_buf_puts(b, tmp) || req_buf_puts(b, "\r\n")) return -1;
    }
    if (!(have & H_UA) && req_buf_puts(b, "User-Agent: libreq/" REQ_VERSION "\r\n")) return -1;
    if (!(have & H_ACCEPT) && req_buf_puts(b, "Accept: */*\r\n")) return -1;
    if (!(have & H_CONN) && req_buf_puts(b, "Connection: keep-alive\r\n")) return -1;
    if (r->body_len && r->content_type && !(have & H_CTYPE)) {
        if (req_buf_puts(b, "Content-Type: ") || req_buf_puts(b, r->content_type) ||
            req_buf_puts(b, "\r\n"))
            return -1;
    }
    if (r->body_len || !strcmp(method, "POST") || !strcmp(method, "PUT") || !strcmp(method, "PATCH")) {
        snprintf(tmp, sizeof(tmp), "Content-Length: %zu\r\n", r->body_len);
        if (req_buf_puts(b, tmp)) return -1;
    }
    if (r->headers) {
        for (i = 0; r->headers[i]; i++) {
            const char *h = r->headers[i];
            size_t nl = (size_t)(strchr(h, ':') - h);
            if (strip_creds && req_is_credential(h, nl)) continue;
            if (req_buf_puts(b, h) || req_buf_puts(b, "\r\n")) return -1;
        }
    }
    if (req_buf_puts(b, "\r\n")) return -1;
    if (inline_body && r->body_len && req_buf_append(b, r->body, r->body_len)) return -1;
    return 0;
}

static int req_idempotent(const char *m) {
    return !strcmp(m, "GET") || !strcmp(m, "HEAD") || !strcmp(m, "PUT") || !strcmp(m, "DELETE") ||
           !strcmp(m, "OPTIONS") || !strcmp(m, "TRACE");
}

static req_err req_once(req_client *c, const req_request *r, const char *method, const req_url *u,
                        int strip_creds, req_response *out) {
    req_conn *cn = NULL;
    req_buf head, hdrs, body;
    req_rd *rd;
    req_err e = REQ_OK;
    int status = 0, keep = 0, attempt, br;
    int inline_body = r->body_len <= REQ_INLINE_BODY;

    memset(&head, 0, sizeof(head));
    memset(&hdrs, 0, sizeof(hdrs));
    memset(&body, 0, sizeof(body));
    br = req_build_head(&head, method, u, r, strip_creds, inline_body);
    if (br) {
        req_buf_free(&head);
        return br == -2 ? REQ_ERR_REJECT : REQ_ERR_OOM;
    }

    /* A pooled connection can die between the liveness check and our write. If the
     * request could not be written it was never seen, so one fresh retry is safe for
     * every method. */
    for (attempt = 0; attempt < 2; attempt++) {
        int64_t deadline;
        cn = attempt == 0 ? req_pool_take(c, u) : NULL;
        if (!cn) {
            cn = req_pool_slot(c);
            if (!cn) {
                req_buf_free(&head);
                return REQ_ERR_IO;
            }
            e = req_connect_host(c, cn, u, req_now_ms() + c->connect_ms);
            if (e) {
                req_buf_free(&head);
                return e;
            }
        }
        deadline = req_now_ms() + c->io_ms;
        e = req_io_write_all(cn, head.p, head.len, deadline);
        if (!e && !inline_body) e = req_io_write_all(cn, r->body, r->body_len, deadline);
        if (!e) break;
        {
            int was_reused = cn->reused;
            req_conn_close(cn);
            if (e == REQ_ERR_TIMEOUT || !was_reused) {
                req_buf_free(&head);
                return e == REQ_ERR_TIMEOUT ? REQ_ERR_TIMEOUT : REQ_ERR_CLOSED;
            }
        }
    }
    req_buf_free(&head);
    if (e) return REQ_ERR_CLOSED;

    rd = (req_rd *)calloc(1, sizeof(*rd));
    if (!rd) {
        req_conn_close(cn);
        return REQ_ERR_OOM;
    }
    rd->cn = cn;
    rd->deadline = req_now_ms() + c->io_ms;
    e = req_read_response(rd, method, c->max_body, &hdrs, &body, &status, &keep);
    free(rd);
    if (e) {
        req_conn_close(cn);
        req_buf_free(&hdrs);
        req_buf_free(&body);
        return e;
    }
    if (!body.p && !(body.p = (char *)calloc(1, 1))) {
        req_conn_close(cn);
        req_buf_free(&hdrs);
        return REQ_ERR_OOM;
    }
    out->status = status;
    out->headers = hdrs.p;
    out->headers_len = hdrs.len;
    out->body = body.p;
    out->body_len = body.len;
    out->err = REQ_OK;
    req_pool_release(cn, keep);
    return REQ_OK;
}

static int req_retryable(req_err e) {
    return e == REQ_ERR_CONNECT || e == REQ_ERR_IO || e == REQ_ERR_TIMEOUT || e == REQ_ERR_CLOSED ||
           e == REQ_ERR_TLS || e == REQ_ERR_DNS;
}

static req_response req_send_url(req_client *c, req_request req) {
    req_url u, origin;
    req_response r;
    const char *method;
    char urlbuf[REQ_URL_MAX], next[REQ_URL_MAX], loc[REQ_URL_MAX];
    int redirs = 0;
    size_t ul;

    memset(&r, 0, sizeof(r));
    if (!c || !req.url) return req_fail(REQ_ERR_URL);
    ul = strlen(req.url);
    if (ul >= sizeof(urlbuf)) return req_fail(REQ_ERR_URL);
    memcpy(urlbuf, req.url, ul + 1);
    method = req.method && req.method[0] ? req.method : "GET";
    if (!req_is_token(method, strlen(method))) return req_fail(REQ_ERR_REJECT);
    if (req.body_len && !req.body) return req_fail(REQ_ERR_REJECT);
    if (req_parse_url(urlbuf, &origin)) return req_fail(REQ_ERR_URL);

    for (;;) {
        req_err last = REQ_ERR_IO;
        int attempt, max_try;
        const char *lv;
        size_t lvl = 0;
        req_url nu;

        if (req_parse_url(urlbuf, &u)) return req_fail(REQ_ERR_URL);
        max_try = req_idempotent(method) ? c->retries + 1 : 1;
        for (attempt = 0; attempt < max_try; attempt++) {
            req_response_free(&r);
            memset(&r, 0, sizeof(r));
            last = req_once(c, &req, method, &u, !req_same_origin(&origin, &u), &r);
            if (last == REQ_OK || !req_retryable(last)) break;
        }
        if (last != REQ_OK) {
            req_response_free(&r);
            return req_fail(last);
        }

        if (c->redirects == 0 || !(r.status == 301 || r.status == 302 || r.status == 303 ||
                                   r.status == 307 || r.status == 308))
            break;
        lv = req_header_find(&r, "Location", &lvl);
        if (!lv || lvl == 0 || lvl >= sizeof(loc)) break;
        memcpy(loc, lv, lvl);
        loc[lvl] = '\0';
        if (req_resolve_ref(&u, loc, next, sizeof(next)) || req_parse_url(next, &nu)) break;
        if (u.tls && !nu.tls) break; /* never downgrade https -> http */
        if (redirs >= c->redirects) {
            req_response_free(&r);
            return req_fail(REQ_ERR_REDIRECTS);
        }
        if ((r.status == 303 && strcmp(method, "HEAD") != 0) ||
            ((r.status == 301 || r.status == 302) && !strcmp(method, "POST"))) {
            method = "GET";
            req.body = NULL;
            req.body_len = 0;
            req.content_type = NULL;
        }
        req.method = method;
        redirs++;
        memcpy(urlbuf, next, strlen(next) + 1);
        req_response_free(&r);
        memset(&r, 0, sizeof(r));
    }

    if (req_format_url(&u, next, sizeof(next)) == 0) r.url = strdup(next);
    if (!r.url) {
        req_response_free(&r);
        return req_fail(REQ_ERR_OOM);
    }
    r.redirects = redirs;
    return r;
}

req_response req_send(req_client *c, const req_request *r) {
    if (!r) return req_fail(REQ_ERR_URL);
    return req_send_url(c, *r);
}

static req_response req_simple(req_client *c, const char *method, const char *url, const void *body,
                               size_t len, const char *ct) {
    req_request r;
    memset(&r, 0, sizeof(r));
    r.method = method;
    r.url = url;
    r.body = body;
    r.body_len = len;
    r.content_type = ct;
    return req_send_url(c, r);
}

req_response req_get(req_client *c, const char *url) { return req_simple(c, "GET", url, NULL, 0, NULL); }

req_response req_head(req_client *c, const char *url) { return req_simple(c, "HEAD", url, NULL, 0, NULL); }

req_response req_delete(req_client *c, const char *url) {
    return req_simple(c, "DELETE", url, NULL, 0, NULL);
}

req_response req_post(req_client *c, const char *url, const void *body, size_t len, const char *ct) {
    return req_simple(c, "POST", url, body, len, ct);
}

req_response req_put(req_client *c, const char *url, const void *body, size_t len, const char *ct) {
    return req_simple(c, "PUT", url, body, len, ct);
}

req_response req_patch(req_client *c, const char *url, const void *body, size_t len, const char *ct) {
    return req_simple(c, "PATCH", url, body, len, ct);
}
