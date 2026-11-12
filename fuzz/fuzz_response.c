/* libFuzzer: HTTP/1.x response parser (status line, headers, framing, chunked). */
#include "../src/req_internal.h"

#include <sys/socket.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    int sv[2], status = 0, ka = 0;
    req_conn cn;
    static req_rd rd;
    req_buf h, b;
    req_err e;
    const char *method = (size && (data[0] & 1)) ? "HEAD" : "GET";
    int buf = 1 << 20;
    if (size > 65536 || socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return 0;
    /* The input is written before it is read: make sure it fits in the socket buffers. */
    setsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));
    setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
    if (size && send(sv[1], data, size, 0) != (ssize_t)size) {
        close(sv[0]);
        close(sv[1]);
        return 0;
    }
    shutdown(sv[1], SHUT_WR);
    memset(&cn, 0, sizeof(cn));
    cn.fd = sv[0];
    memset(&rd, 0, sizeof(rd));
    memset(&h, 0, sizeof(h));
    memset(&b, 0, sizeof(b));
    rd.cn = &cn;
    rd.deadline = req_now_ms() + 1000;
    e = req_read_response(&rd, method, 4096, &h, &b, &status, &ka);
    if (e == REQ_OK) {
        if (status < 100 || status > 599 || b.len > 4096) __builtin_trap();
        if (b.p && b.p[b.len] != '\0') __builtin_trap();
        if (!h.p || h.len < 4 || memcmp(h.p + h.len - 4, "\r\n\r\n", 4) != 0) __builtin_trap();
    }
    req_buf_free(&h);
    req_buf_free(&b);
    close(sv[0]);
    close(sv[1]);
    return 0;
}
