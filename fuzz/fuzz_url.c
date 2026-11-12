/* libFuzzer: URL parser, formatter round-trip and RFC 3986 reference resolution. */
#include "../src/req_internal.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char in[REQ_URL_MAX + 1], out[REQ_URL_MAX], res[REQ_URL_MAX];
    req_url u, u2, base;
    if (size > REQ_URL_MAX) return 0;
    memcpy(in, data, size);
    in[size] = '\0';

    if (req_parse_url(in, &u) == 0) {
        /* Invariants of a parsed URL. */
        if (u.path[0] != '/' || u.port < 1 || u.port > 65535 || !u.host[0]) __builtin_trap();
        if (strpbrk(u.path, " \r\n#")) __builtin_trap();
        /* Round trip: format + reparse yields the same URL. */
        if (req_format_url(&u, out, sizeof(out)) == 0) {
            if (req_parse_url(out, &u2) != 0) __builtin_trap();
            if (u.tls != u2.tls || u.port != u2.port || u.ipv6 != u2.ipv6 || strcmp(u.host, u2.host) ||
                strcmp(u.path, u2.path))
                __builtin_trap();
        }
    }

    if (req_parse_url("http://a/b/c/d;p?q", &base) == 0 && req_resolve_ref(&base, in, res, sizeof(res)) == 0) {
        if (req_parse_url(res, &u2) == 0 && strstr(u2.path, "/../") && !strchr(u2.path, '?')) __builtin_trap();
    }
    return 0;
}
