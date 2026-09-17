#include "req_internal.h"

static int req_poll_fd(int fd, short ev, int64_t deadline) {
    struct pollfd p;
    int ms, rc;
    p.fd = fd;
    p.events = ev;
    p.revents = 0;
    ms = req_remain_ms(deadline);
    if (ms <= 0) return -2;
    rc = poll(&p, 1, ms);
    if (rc == 0) return -2;
    if (rc < 0) return -1;
    if (p.revents & POLLNVAL) return -1;
    if (p.revents & ev) return 0;
    if (p.revents & (POLLERR | POLLHUP)) return -1;
    return -1;
}

static int req_set_nonblock(int fd, int nb) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    if (nb) fl |= O_NONBLOCK;
    else fl &= ~O_NONBLOCK;
    return fcntl(fd, F_SETFL, fl);
}

void req_conn_close(req_conn *cn) {
    if (!cn) return;
#ifdef REQ_USE_OPENSSL
    if (cn->ssl) {
        SSL_shutdown(cn->ssl);
        SSL_free(cn->ssl);
        cn->ssl = NULL;
    }
#endif
    if (cn->fd >= 0) {
        close(cn->fd);
        cn->fd = -1;
    }
    cn->in_use = 0;
    cn->host[0] = '\0';
}

#ifdef REQ_USE_OPENSSL
static int req_tls_handshake(req_client *c, req_conn *cn, const char *host, int64_t deadline) {
    int rc, err;
    cn->ssl = SSL_new(c->ctx);
    if (!cn->ssl) return REQ_ERR_TLS;
    SSL_set_fd(cn->ssl, cn->fd);
    SSL_set_tlsext_host_name(cn->ssl, host);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    SSL_set1_host(cn->ssl, host);
#endif
    if (c->insecure) SSL_set_verify(cn->ssl, SSL_VERIFY_NONE, NULL);

    for (;;) {
        rc = SSL_connect(cn->ssl);
        if (rc == 1) return REQ_OK;
        err = SSL_get_error(cn->ssl, rc);
        if (err == SSL_ERROR_WANT_READ) {
            int p = req_poll_fd(cn->fd, POLLIN, deadline);
            if (p == -2) return REQ_ERR_TIMEOUT;
            if (p < 0) return REQ_ERR_TLS;
            continue;
        }
        if (err == SSL_ERROR_WANT_WRITE) {
            if (req_poll_fd(cn->fd, POLLOUT, deadline) < 0) {
                return req_remain_ms(deadline) <= 0 ? REQ_ERR_TIMEOUT : REQ_ERR_TLS;
            }
            continue;
        }
        return REQ_ERR_TLS;
    }
}
#endif

int req_io_read(req_conn *cn, void *buf, int n, int64_t deadline) {
#ifdef REQ_USE_OPENSSL
    if (cn->ssl) {
        for (;;) {
            int rc = SSL_read(cn->ssl, buf, n);
            int err;
            if (rc > 0) return rc;
            if (rc == 0) return 0;
            err = SSL_get_error(cn->ssl, rc);
            if (err == SSL_ERROR_WANT_READ) {
                int p = req_poll_fd(cn->fd, POLLIN, deadline);
                if (p == -2) return -2;
                if (p < 0) return -1;
                continue;
            }
            if (err == SSL_ERROR_WANT_WRITE) {
                int p = req_poll_fd(cn->fd, POLLOUT, deadline);
                if (p == -2) return -2;
                if (p < 0) return -1;
                continue;
            }
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
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
        return -1;
    }
}

int req_io_write_all(req_conn *cn, const void *buf, size_t n, int64_t deadline) {
    const char *p = (const char *)buf;
    size_t off = 0;
    while (off < n) {
        int chunk = n - off > 1u << 20 ? 1 << 20 : (int)(n - off);
#ifdef REQ_USE_OPENSSL
        if (cn->ssl) {
            int rc = SSL_write(cn->ssl, p + off, chunk);
            int err;
            if (rc > 0) {
                off += (size_t)rc;
                continue;
            }
            err = SSL_get_error(cn->ssl, rc);
            if (err == SSL_ERROR_WANT_READ) {
                if (req_poll_fd(cn->fd, POLLIN, deadline) == -2) return REQ_ERR_TIMEOUT;
                continue;
            }
            if (err == SSL_ERROR_WANT_WRITE) {
                if (req_poll_fd(cn->fd, POLLOUT, deadline) == -2) return REQ_ERR_TIMEOUT;
                continue;
            }
            return REQ_ERR_IO;
        }
#endif
        {
            int pr = req_poll_fd(cn->fd, POLLOUT, deadline);
            ssize_t rc;
            if (pr == -2) return REQ_ERR_TIMEOUT;
            if (pr < 0) return REQ_ERR_IO;
            rc = send(cn->fd, p + off, (size_t)chunk, 0);
            if (rc > 0) {
                off += (size_t)rc;
                continue;
            }
            if (rc < 0 && errno == EINTR) continue;
            if (rc < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
            return REQ_ERR_IO;
        }
    }
    return REQ_OK;
}

static int req_tcp_connect(const char *host, int port, int64_t deadline) {
    struct addrinfo hints, *res = NULL, *rp;
    char portstr[16];
    int fd = -1, rc;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    snprintf(portstr, sizeof(portstr), "%d", port);
    rc = getaddrinfo(host, portstr, &hints, &res);
    if (rc != 0) return -3; /* dns */

    for (rp = res; rp; rp = rp->ai_next) {
        int one = 1;
        fd = (int)socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        if (req_set_nonblock(fd, 1) < 0) {
            close(fd);
            fd = -1;
            continue;
        }
        rc = connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (rc == 0) break;
        if (errno != EINPROGRESS) {
            close(fd);
            fd = -1;
            continue;
        }
        {
            struct pollfd p;
            int ms, soerr = 0;
            socklen_t sl = sizeof(soerr);
            p.fd = fd;
            p.events = POLLOUT;
            p.revents = 0;
            ms = req_remain_ms(deadline);
            if (ms <= 0) {
                close(fd);
                fd = -1;
                freeaddrinfo(res);
                return -2;
            }
            rc = poll(&p, 1, ms);
            if (rc <= 0 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) < 0 || soerr != 0) {
                close(fd);
                fd = -1;
                if (rc == 0) {
                    freeaddrinfo(res);
                    return -2;
                }
                continue;
            }
            break;
        }
    }
    freeaddrinfo(res);
    return fd;
}

int req_connect_host(req_client *c, req_conn *cn, const req_url *u, int64_t deadline) {
    int fd;
    memset(cn, 0, sizeof(*cn));
    cn->fd = -1;
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
        int te = req_tls_handshake(c, cn, u->host, deadline);
        if (te != REQ_OK) {
            req_conn_close(cn);
            return te;
        }
    }
#else
    if (u->tls) {
        req_conn_close(cn);
        return REQ_ERR_TLS;
    }
    (void)c;
#endif
    cn->in_use = 1;
    return REQ_OK;
}
