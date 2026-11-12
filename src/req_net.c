#include "req_internal.h"

/* 0 ready, -1 error/hangup, -2 timeout */
static int req_poll_fd(int fd, short ev, int64_t deadline) {
    for (;;) {
        struct pollfd p;
        int ms, rc;
        p.fd = fd;
        p.events = ev;
        p.revents = 0;
        ms = req_remain_ms(deadline);
        if (ms <= 0) return -2;
        rc = poll(&p, 1, ms);
        if (rc == 0) return -2;
        if (rc < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (p.revents & POLLNVAL) return -1;
        if (p.revents & ev) return 0;
        /* POLLHUP with POLLIN requested is reported as readable so EOF is observed by read */
        if ((ev & POLLIN) && (p.revents & POLLHUP)) return 0;
        return -1;
    }
}

static int req_set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

void req_conn_close(req_conn *cn) {
    if (!cn) return;
#ifdef REQ_USE_OPENSSL
    if (cn->ssl) {
        /* Best-effort close_notify; the BIO never raises SIGPIPE. */
        if (SSL_is_init_finished(cn->ssl)) SSL_shutdown(cn->ssl);
        ERR_clear_error();
        SSL_free(cn->ssl);
        cn->ssl = NULL;
    }
#endif
    if (cn->fd >= 0) {
        close(cn->fd);
        cn->fd = -1;
    }
    cn->in_use = 0;
    cn->reused = 0;
    cn->host[0] = '\0';
}

int req_conn_alive(req_conn *cn) {
    struct pollfd p;
    int rc;
    if (cn->fd < 0) return 0;
    p.fd = cn->fd;
    p.events = POLLIN;
    p.revents = 0;
    do {
        rc = poll(&p, 1, 0);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0) return 0;
    if (rc == 0) return 1;
    if (p.revents & (POLLERR | POLLNVAL)) return 0;
#ifdef REQ_USE_OPENSSL
    if (cn->ssl) {
        /* Readable TLS may only carry post-handshake records (e.g. TLS 1.3 session tickets). */
        char b;
        int r = SSL_peek(cn->ssl, &b, 1);
        if (r > 0) return 0; /* unsolicited application data */
        if (SSL_get_error(cn->ssl, r) == SSL_ERROR_WANT_READ) {
            ERR_clear_error();
            return 1;
        }
        ERR_clear_error();
        return 0;
    }
#endif
    return 0; /* EOF or stray bytes on an idle plain connection */
}

#ifdef REQ_USE_OPENSSL
/* A socket BIO that uses send(MSG_NOSIGNAL) so a peer reset never kills the process. */
static int req_bio_write(BIO *b, const char *buf, int len) {
    int fd = (int)(intptr_t)BIO_get_data(b);
    ssize_t rc;
    BIO_clear_retry_flags(b);
    if (len <= 0) return 0;
    rc = send(fd, buf, (size_t)len, REQ_SEND_FLAGS);
    if (rc < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) BIO_set_retry_write(b);
    return (int)rc;
}

static int req_bio_read(BIO *b, char *buf, int len) {
    int fd = (int)(intptr_t)BIO_get_data(b);
    ssize_t rc;
    BIO_clear_retry_flags(b);
    if (len <= 0) return 0;
    rc = recv(fd, buf, (size_t)len, 0);
    if (rc < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) BIO_set_retry_read(b);
    return (int)rc;
}

static long req_bio_ctrl(BIO *b, int cmd, long num, void *ptr) {
    (void)b;
    (void)num;
    (void)ptr;
    switch (cmd) {
    case BIO_CTRL_FLUSH:
    case BIO_CTRL_DUP:
        return 1;
    default:
        return 0;
    }
}

static int req_bio_create(BIO *b) {
    BIO_set_init(b, 1);
    return 1;
}

static int req_bio_destroy(BIO *b) {
    (void)b;
    return 1;
}

BIO_METHOD *req_bio_method_new(void) {
    BIO_METHOD *m = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "libreq socket");
    if (!m) return NULL;
    if (!BIO_meth_set_write(m, req_bio_write) || !BIO_meth_set_read(m, req_bio_read) ||
        !BIO_meth_set_ctrl(m, req_bio_ctrl) || !BIO_meth_set_create(m, req_bio_create) ||
        !BIO_meth_set_destroy(m, req_bio_destroy)) {
        BIO_meth_free(m);
        return NULL;
    }
    return m;
}

static int req_is_ip_literal(const char *host) {
    unsigned char a[16];
    return inet_pton(AF_INET, host, a) == 1 || inet_pton(AF_INET6, host, a) == 1;
}

static req_err req_tls_handshake(req_client *c, req_conn *cn, const char *host, int64_t deadline) {
    static const unsigned char alpn[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    BIO *bio;
    int rc, err;
    cn->ssl = SSL_new(c->ctx);
    if (!cn->ssl) return REQ_ERR_TLS;
    bio = BIO_new(c->bio_meth);
    if (!bio) return REQ_ERR_OOM;
    BIO_set_data(bio, (void *)(intptr_t)cn->fd);
    SSL_set_bio(cn->ssl, bio, bio);
    SSL_set_alpn_protos(cn->ssl, alpn, sizeof(alpn));

    if (req_is_ip_literal(host)) {
        /* RFC 6066: no SNI for IP literals; verify against iPAddress SANs. */
        if (!c->insecure && !X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(cn->ssl), host))
            return REQ_ERR_TLS;
    } else {
        if (!SSL_set_tlsext_host_name(cn->ssl, host)) return REQ_ERR_TLS;
        if (!c->insecure) {
            SSL_set_hostflags(cn->ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
            if (!SSL_set1_host(cn->ssl, host)) return REQ_ERR_TLS;
        }
    }
    if (c->insecure) SSL_set_verify(cn->ssl, SSL_VERIFY_NONE, NULL);

    for (;;) {
        rc = SSL_connect(cn->ssl);
        if (rc == 1) {
            ERR_clear_error();
            return REQ_OK;
        }
        err = SSL_get_error(cn->ssl, rc);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            int p = req_poll_fd(cn->fd, err == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, deadline);
            if (p == -2) return REQ_ERR_TIMEOUT;
            if (p < 0) return REQ_ERR_TLS;
            continue;
        }
        ERR_clear_error();
        if (!c->insecure && SSL_get_verify_result(cn->ssl) != X509_V_OK) return REQ_ERR_TLS_VERIFY;
        return REQ_ERR_TLS;
    }
}
#endif

int req_io_read(req_conn *cn, void *buf, int n, int64_t deadline) {
#ifdef REQ_USE_OPENSSL
    if (cn->ssl) {
        for (;;) {
            int rc = SSL_read(cn->ssl, buf, n);
            int err, p;
            if (rc > 0) return rc;
            err = SSL_get_error(cn->ssl, rc);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                p = req_poll_fd(cn->fd, err == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, deadline);
                if (p == -2) return -2;
                if (p < 0) return -1;
                continue;
            }
            ERR_clear_error();
            if (err == SSL_ERROR_ZERO_RETURN) return 0;
            return -1;
        }
    }
#endif
    for (;;) {
        ssize_t rc;
        int p = req_poll_fd(cn->fd, POLLIN, deadline);
        if (p == -2) return -2;
        if (p < 0) return -1;
        rc = recv(cn->fd, buf, (size_t)n, 0);
        if (rc > 0) return (int)rc;
        if (rc == 0) return 0;
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
        return -1;
    }
}

req_err req_io_write_all(req_conn *cn, const void *buf, size_t n, int64_t deadline) {
    const char *p = (const char *)buf;
    size_t off = 0;
    while (off < n) {
        int chunk = n - off > (1u << 20) ? (1 << 20) : (int)(n - off);
        int pr;
#ifdef REQ_USE_OPENSSL
        if (cn->ssl) {
            int rc = SSL_write(cn->ssl, p + off, chunk);
            int err;
            if (rc > 0) {
                off += (size_t)rc;
                continue;
            }
            err = SSL_get_error(cn->ssl, rc);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                pr = req_poll_fd(cn->fd, err == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, deadline);
                if (pr == -2) return REQ_ERR_TIMEOUT;
                if (pr < 0) return REQ_ERR_IO;
                continue;
            }
            ERR_clear_error();
            return REQ_ERR_IO;
        }
#endif
        {
            ssize_t rc;
            pr = req_poll_fd(cn->fd, POLLOUT, deadline);
            if (pr == -2) return REQ_ERR_TIMEOUT;
            if (pr < 0) return REQ_ERR_IO;
            rc = send(cn->fd, p + off, (size_t)chunk, REQ_SEND_FLAGS);
            if (rc > 0) {
                off += (size_t)rc;
                continue;
            }
            if (rc < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
            return REQ_ERR_IO;
        }
    }
    return REQ_OK;
}

static int req_socket(int family, int type, int proto) {
    int fd, one = 1;
#ifdef SOCK_CLOEXEC
    fd = socket(family, type | SOCK_CLOEXEC, proto);
#else
    fd = socket(family, type, proto);
    if (fd >= 0) fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif
    if (fd < 0) return -1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#ifdef SO_NOSIGPIPE
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
    if (req_set_nonblock(fd) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* fd >= 0, -1 connect failed, -2 timeout, -3 dns */
static int req_tcp_connect(const char *host, int port, int64_t deadline) {
    struct addrinfo hints, *res = NULL, *rp;
    char portstr[16];
    int fd = -1, rc, left = 0, saw_timeout = 0;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_ADDRCONFIG;
    snprintf(portstr, sizeof(portstr), "%d", port);
    rc = getaddrinfo(host, portstr, &hints, &res);
#ifdef EAI_ADDRFAMILY
    if (rc == EAI_NONAME || rc == EAI_ADDRFAMILY) {
#else
    if (rc == EAI_NONAME) {
#endif
        hints.ai_flags = 0; /* AI_ADDRCONFIG hides loopback-only hosts on some systems */
        rc = getaddrinfo(host, portstr, &hints, &res);
    }
    if (rc != 0) return -3;
    for (rp = res; rp; rp = rp->ai_next) left++;

    for (rp = res; rp; rp = rp->ai_next, left--) {
        int64_t attempt_deadline = deadline;
        int remain = req_remain_ms(deadline);
        if (remain <= 0) {
            saw_timeout = 1;
            break;
        }
        /* Give each address a share of the budget so one black-holed address
         * (typically IPv6) cannot eat the entire connect timeout. */
        if (left > 1) {
            int share = remain / left;
            if (share < 250) share = remain < 250 ? remain : 250;
            attempt_deadline = req_now_ms() + share;
        }
        fd = req_socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        rc = connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (rc == 0) break;
        if (errno == EINPROGRESS || errno == EINTR) {
            int soerr = 0;
            socklen_t sl = sizeof(soerr);
            int pr = req_poll_fd(fd, POLLOUT, attempt_deadline);
            if (pr == 0 && getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) == 0 && soerr == 0) break;
            if (pr == -2) saw_timeout = 1;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) return saw_timeout ? -2 : -1;
    return fd;
}

req_err req_connect_host(req_client *c, req_conn *cn, const req_url *u, int64_t deadline) {
    int fd;
    memset(cn, 0, sizeof(*cn));
    cn->fd = -1;
#ifndef REQ_USE_OPENSSL
    if (u->tls) return REQ_ERR_TLS;
#endif
    fd = req_tcp_connect(u->host, u->port, deadline);
    if (fd == -3) return REQ_ERR_DNS;
    if (fd == -2) return REQ_ERR_TIMEOUT;
    if (fd < 0) return REQ_ERR_CONNECT;
    cn->fd = fd;
    cn->tls = u->tls;
    cn->port = u->port;
    snprintf(cn->host, sizeof(cn->host), "%s", u->host);
#ifdef REQ_USE_OPENSSL
    if (u->tls) {
        req_err te = req_tls_handshake(c, cn, u->host, deadline);
        if (te != REQ_OK) {
            req_conn_close(cn);
            return te;
        }
    }
#else
    (void)c;
#endif
    cn->in_use = 1;
    return REQ_OK;
}
