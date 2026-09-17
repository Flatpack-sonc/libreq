#include "req_internal.h"

int req_has_crlf(const char *s, size_t n) {
    size_t i;
    if (!s) return 0;
    for (i = 0; i < n; i++) {
        if (s[i] == '\r' || s[i] == '\n') return 1;
    }
    return 0;
}

static int req_copy_tok(char *dst, size_t dstsz, const char *src, size_t n) {
    if (n + 1u > dstsz) return -1;
    memcpy(dst, src, n);
    dst[n] = '\0';
    return 0;
}

int req_parse_url(const char *url, req_url *out) {
    const char *p, *host, *path, *colon;
    size_t n;
    memset(out, 0, sizeof(*out));
    if (!url || !*url) return -1;
    if (req_has_crlf(url, strlen(url))) return -1;

    if (!strncmp(url, "https://", 8)) {
        out->tls = 1;
        out->port = 443;
        p = url + 8;
    } else if (!strncmp(url, "http://", 7)) {
        out->tls = 0;
        out->port = 80;
        p = url + 7;
    } else {
        return -1;
    }

    if (*p == '[') {
        const char *end = strchr(p, ']');
        if (!end || end == p + 1) return -1;
        if (req_copy_tok(out->host, sizeof(out->host), p + 1, (size_t)(end - p - 1))) return -1;
        p = end + 1;
        if (*p == ':') {
            char *ep = NULL;
            long v = strtol(p + 1, &ep, 10);
            if (ep == p + 1 || v <= 0 || v > 65535) return -1;
            out->port = (int)v;
            p = ep;
        }
    } else {
        host = p;
        path = host;
        while (*path && *path != '/' && *path != '?' && *path != ':') path++;
        if (*path == ':') {
            colon = path;
            if (req_copy_tok(out->host, sizeof(out->host), host, (size_t)(colon - host))) return -1;
            {
                char *ep = NULL;
                long v = strtol(colon + 1, &ep, 10);
                if (ep == colon + 1 || v <= 0 || v > 65535) return -1;
                out->port = (int)v;
                p = ep;
            }
        } else {
            if (req_copy_tok(out->host, sizeof(out->host), host, (size_t)(path - host))) return -1;
            p = path;
        }
    }

    if (!out->host[0]) return -1;
    if (strchr(out->host, '/') || strchr(out->host, ' ')) return -1;

    if (*p == '\0' || *p == '/') {
        if (*p == '\0') {
            memcpy(out->path, "/", 2);
        } else {
            n = strlen(p);
            if (n >= sizeof(out->path)) return -1;
            memcpy(out->path, p, n + 1);
        }
    } else if (*p == '?') {
        if (strlen(p) + 2u >= sizeof(out->path)) return -1;
        out->path[0] = '/';
        memcpy(out->path + 1, p, strlen(p) + 1);
    } else {
        return -1;
    }

    {
        char *hash = strchr(out->path, '#');
        if (hash) *hash = '\0';
    }
    return 0;
}

int req_buf_grow(req_buf *b, size_t need) {
    size_t ncap;
    char *np;
    if (need <= b->cap) return 0;
    ncap = b->cap ? b->cap : 256u;
    while (ncap < need) {
        if (ncap > SIZE_MAX / 2u) {
            ncap = need;
            break;
        }
        ncap *= 2u;
    }
    np = (char *)realloc(b->p, ncap);
    if (!np) return -1;
    b->p = np;
    b->cap = ncap;
    return 0;
}

void req_buf_free(req_buf *b) {
    free(b->p);
    b->p = NULL;
    b->len = b->cap = 0;
}

int req_buf_append(req_buf *b, const void *s, size_t n) {
    size_t need;
    if (!n) return 0;
    if (!req_add_ok(b->len, n, &need) || !req_add_ok(need, 1, &need)) return -1;
    if (req_buf_grow(b, need)) return -1;
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = '\0';
    return 0;
}
