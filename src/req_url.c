#include "req_internal.h"

int req_has_crlf(const char *s, size_t n) {
    size_t i;
    if (!s) return 0;
    for (i = 0; i < n; i++) {
        if (s[i] == '\r' || s[i] == '\n') return 1;
    }
    return 0;
}

int req_ascii_ieq(const char *a, const char *b, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        if (req_lower((unsigned char)a[i]) != req_lower((unsigned char)b[i])) return 0;
    }
    return 1;
}

int req_is_token(const char *s, size_t n) {
    size_t i;
    if (!s || !n) return 0;
    for (i = 0; i < n; i++) {
        if (!req_is_tchar((unsigned char)s[i])) return 0;
    }
    return 1;
}

static int req_scheme_len(const char *s) {
    int i = 0;
    if (!((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= 'A' && s[0] <= 'Z'))) return 0;
    for (i = 1; s[i]; i++) {
        unsigned char ch = (unsigned char)s[i];
        if (ch == ':') return i;
        if (!(isalnum(ch) || ch == '+' || ch == '-' || ch == '.')) return 0;
    }
    return 0;
}

static int req_host_char(unsigned char ch) {
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
           ch == '-' || ch == '.' || ch == '_';
}

/* Copies the path/query part, percent-encoding bytes that are never valid on the wire. */
static int req_copy_target(char *dst, size_t dstsz, const char *src, size_t n, int add_slash) {
    static const char hex[] = "0123456789ABCDEF";
    size_t i, o = 0;
    if (add_slash) {
        if (dstsz < 2) return -1;
        dst[o++] = '/';
    }
    for (i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)src[i];
        if (ch < 0x20 || ch == 0x7f) return -1;
        if (ch == ' ' || ch == '"' || ch == '<' || ch == '>' || ch == '`' || ch >= 0x80) {
            if (o + 3 >= dstsz) return -1;
            dst[o++] = '%';
            dst[o++] = hex[ch >> 4];
            dst[o++] = hex[ch & 15];
        } else {
            if (o + 1 >= dstsz) return -1;
            dst[o++] = (char)ch;
        }
    }
    if (o == 0) {
        if (dstsz < 2) return -1;
        dst[o++] = '/';
    }
    dst[o] = '\0';
    return 0;
}

static int req_parse_port(const char *s, size_t n, int *port) {
    size_t i;
    long v = 0;
    if (n == 0) return 0; /* "host:" means the default port */
    if (n > 5) return -1;
    for (i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        v = v * 10 + (s[i] - '0');
    }
    if (v < 1 || v > 65535) return -1;
    *port = (int)v;
    return 0;
}

int req_parse_url(const char *url, req_url *out) {
    const char *p, *auth, *auth_end, *hs, *he, *ps = NULL, *pe = NULL, *rest, *frag;
    size_t n, i;
    int sl;
    memset(out, 0, sizeof(*out));
    if (!url || !*url) return -1;
    n = strlen(url);
    if (n >= REQ_URL_MAX || req_has_crlf(url, n)) return -1;

    sl = req_scheme_len(url);
    if (sl == 5 && req_ascii_ieq(url, "https", 5)) {
        out->tls = 1;
        out->port = 443;
    } else if (sl == 4 && req_ascii_ieq(url, "http", 4)) {
        out->tls = 0;
        out->port = 80;
    } else {
        return -1;
    }
    p = url + sl + 1;
    if (p[0] != '/' || p[1] != '/') return -1;
    auth = p + 2;
    auth_end = auth + strcspn(auth, "/?#");
    if (memchr(auth, '@', (size_t)(auth_end - auth))) return -1; /* no userinfo */

    if (*auth == '[') {
        char tmp[64];
        struct in6_addr a6;
        const char *rb = memchr(auth, ']', (size_t)(auth_end - auth));
        if (!rb) return -1;
        hs = auth + 1;
        he = rb;
        if ((size_t)(he - hs) >= sizeof(tmp) || he == hs) return -1;
        memcpy(tmp, hs, (size_t)(he - hs));
        tmp[he - hs] = '\0';
        if (inet_pton(AF_INET6, tmp, &a6) != 1) return -1;
        out->ipv6 = 1;
        if (rb + 1 < auth_end) {
            if (rb[1] != ':') return -1;
            ps = rb + 2;
            pe = auth_end;
        }
    } else {
        const char *colon = memchr(auth, ':', (size_t)(auth_end - auth));
        hs = auth;
        he = colon ? colon : auth_end;
        if (colon) {
            ps = colon + 1;
            pe = auth_end;
        }
        for (i = 0; i < (size_t)(he - hs); i++) {
            if (!req_host_char((unsigned char)hs[i])) return -1;
        }
    }
    if (he == hs || (size_t)(he - hs) >= sizeof(out->host)) return -1;
    for (i = 0; i < (size_t)(he - hs); i++) out->host[i] = (char)req_lower((unsigned char)hs[i]);
    out->host[i] = '\0';
    if (ps && req_parse_port(ps, (size_t)(pe - ps), &out->port)) return -1;

    rest = auth_end;
    frag = strchr(rest, '#');
    n = frag ? (size_t)(frag - rest) : strlen(rest);
    return req_copy_target(out->path, sizeof(out->path), rest, n, n > 0 && rest[0] == '?');
}

int req_format_authority(const req_url *u, char *out, size_t outsz) {
    int n;
    int dflt = (u->tls && u->port == 443) || (!u->tls && u->port == 80);
    if (dflt) n = snprintf(out, outsz, u->ipv6 ? "[%s]" : "%s", u->host);
    else n = snprintf(out, outsz, u->ipv6 ? "[%s]:%d" : "%s:%d", u->host, u->port);
    return (n < 0 || (size_t)n >= outsz) ? -1 : 0;
}

int req_format_url(const req_url *u, char *out, size_t outsz) {
    char auth[300];
    int n;
    if (req_format_authority(u, auth, sizeof(auth))) return -1;
    n = snprintf(out, outsz, "%s://%s%s", u->tls ? "https" : "http", auth, u->path);
    return (n < 0 || (size_t)n >= outsz) ? -1 : 0;
}

int req_same_origin(const req_url *a, const req_url *b) {
    return a->tls == b->tls && a->port == b->port && strcmp(a->host, b->host) == 0;
}

/* RFC 3986 5.2.4. `in` is modified. */
static int req_remove_dots(char *in, char *out, size_t outsz) {
    size_t o = 0;
    char *p = in;
    while (*p) {
        if (!strncmp(p, "../", 3)) p += 3;
        else if (!strncmp(p, "./", 2)) p += 2;
        else if (!strncmp(p, "/./", 3)) p += 2;
        else if (!strcmp(p, "/.")) {
            p += 1;
            *p = '/';
        } else if (!strncmp(p, "/../", 4) || !strcmp(p, "/..")) {
            if (p[3] == '/') p += 3;
            else {
                p += 2;
                *p = '/';
            }
            while (o > 0 && out[o - 1] != '/') o--;
            if (o > 0) o--;
        } else if (!strcmp(p, ".") || !strcmp(p, "..")) {
            break;
        } else {
            size_t seg = 1 + strcspn(p + 1, "/");
            if (*p != '/') seg = strcspn(p, "/");
            if (o + seg >= outsz) return -1;
            memcpy(out + o, p, seg);
            o += seg;
            p += seg;
        }
    }
    if (o == 0) {
        if (outsz < 2) return -1;
        out[o++] = '/';
    }
    out[o] = '\0';
    return 0;
}

int req_resolve_ref(const req_url *base, const char *ref, char *out, size_t outsz) {
    char r[REQ_URL_MAX], merged[REQ_URL_MAX * 2], path[REQ_URL_MAX], auth[300];
    const char *rq, *bq;
    size_t rn, rpath_len;
    int sl, n;
    if (!ref) return -1;
    rn = strcspn(ref, "#");
    if (rn >= sizeof(r)) return -1;
    memcpy(r, ref, rn);
    r[rn] = '\0';
    while (rn && (r[rn - 1] == ' ' || r[rn - 1] == '\t')) r[--rn] = '\0';

    sl = req_scheme_len(r);
    if (sl || (r[0] == '/' && r[1] == '/')) {
        /* Absolute or network-path reference: parse it, then normalize its path. */
        req_url abs;
        char *q;
        if (sl && !((sl == 4 && req_ascii_ieq(r, "http", 4)) || (sl == 5 && req_ascii_ieq(r, "https", 5))))
            return -1;
        n = snprintf(merged, sizeof(merged), "%s%s", sl ? "" : (base->tls ? "https:" : "http:"), r);
        if (n < 0 || (size_t)n >= sizeof(merged) || req_parse_url(merged, &abs)) return -1;
        q = strchr(abs.path, '?');
        if (q) *q = '\0';
        if (req_remove_dots(abs.path, path, sizeof(path))) return -1;
        n = snprintf(merged, sizeof(merged), "%s%s", path, q ? "?" : "");
        if (n < 0 || (size_t)n >= sizeof(merged)) return -1;
        if (q) {
            size_t ml = strlen(merged), ql = strlen(q + 1);
            if (ml + ql >= sizeof(merged)) return -1;
            memcpy(merged + ml, q + 1, ql + 1);
        }
        if (strlen(merged) >= sizeof(abs.path)) return -1;
        memcpy(abs.path, merged, strlen(merged) + 1);
        return req_format_url(&abs, out, outsz);
    }
    if (req_format_authority(base, auth, sizeof(auth))) return -1;

    rq = strchr(r, '?');
    rpath_len = rq ? (size_t)(rq - r) : strlen(r);
    bq = strchr(base->path, '?');
    if (rpath_len == 0) {
        size_t bl = bq ? (size_t)(bq - base->path) : strlen(base->path);
        n = snprintf(out, outsz, "%s://%s%.*s%s", base->tls ? "https" : "http", auth, (int)bl,
                     base->path, rq ? rq : (bq ? bq : ""));
        return (n < 0 || (size_t)n >= outsz) ? -1 : 0;
    }
    if (r[0] == '/') {
        if (rpath_len >= sizeof(merged)) return -1;
        memcpy(merged, r, rpath_len);
        merged[rpath_len] = '\0';
    } else {
        size_t bl = bq ? (size_t)(bq - base->path) : strlen(base->path);
        while (bl > 0 && base->path[bl - 1] != '/') bl--;
        if (bl + rpath_len >= sizeof(merged)) return -1;
        memcpy(merged, base->path, bl);
        memcpy(merged + bl, r, rpath_len);
        merged[bl + rpath_len] = '\0';
    }
    if (req_remove_dots(merged, path, sizeof(path))) return -1;
    n = snprintf(out, outsz, "%s://%s%s%s", base->tls ? "https" : "http", auth, path, rq ? rq : "");
    return (n < 0 || (size_t)n >= outsz) ? -1 : 0;
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

int req_buf_puts(req_buf *b, const char *s) { return req_buf_append(b, s, strlen(s)); }
