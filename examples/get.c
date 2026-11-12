/* Minimal curl-like CLI built on libreq.
 *
 *   get [-i] [-I] [-k] [-v] [-X METHOD] [-H "Name: value"]... [-d DATA] [-c CA.pem]
 *       [-t SECONDS] [-L MAX] URL
 */
#include "req.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_HDRS 64

static void usage(void) {
    fprintf(stderr,
            "usage: get [options] URL\n"
            "  -X METHOD   request method (default GET, or POST with -d)\n"
            "  -H HEADER   extra header \"Name: value\" (repeatable)\n"
            "  -d DATA     request body (@file reads it from a file)\n"
            "  -i          print response headers\n"
            "  -I          HEAD request\n"
            "  -k          skip TLS verification\n"
            "  -c FILE     trust this CA bundle instead of the system store\n"
            "  -t SECONDS  I/O timeout\n"
            "  -L MAX      max redirects (0 disables)\n"
            "  -v          print the final URL and redirect count to stderr\n");
}

static char *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    char *buf = NULL;
    size_t cap = 0, n = 0;
    if (!f) return NULL;
    for (;;) {
        size_t r;
        if (n == cap) {
            char *nb = (char *)realloc(buf, cap ? cap * 2 : 65536);
            if (!nb) {
                free(buf);
                fclose(f);
                return NULL;
            }
            buf = nb;
            cap = cap ? cap * 2 : 65536;
        }
        r = fread(buf + n, 1, cap - n, f);
        n += r;
        if (r == 0) break;
    }
    fclose(f);
    *len = n;
    return buf;
}

int main(int argc, char **argv) {
    const char *hdrs[MAX_HDRS + 1];
    int nh = 0, opt, show_headers = 0, verbose = 0, rc = 0;
    char *data = NULL;
    size_t data_len = 0;
    req_request q;
    req_response r;
    req_client *c = req_client_new();

    if (!c) return 1;
    memset(&q, 0, sizeof(q));
    while ((opt = getopt(argc, argv, "X:H:d:iIkc:t:L:vh")) != -1) {
        switch (opt) {
        case 'X': q.method = optarg; break;
        case 'H':
            if (nh == MAX_HDRS) {
                fprintf(stderr, "too many headers\n");
                return 2;
            }
            hdrs[nh++] = optarg;
            break;
        case 'd':
            if (optarg[0] == '@') {
                data = slurp(optarg + 1, &data_len);
                if (!data) {
                    perror(optarg + 1);
                    return 2;
                }
            } else {
                data_len = strlen(optarg);
                data = (char *)malloc(data_len + 1);
                if (!data) return 1;
                memcpy(data, optarg, data_len + 1);
            }
            break;
        case 'i': show_headers = 1; break;
        case 'I': q.method = "HEAD"; show_headers = 1; break;
        case 'k': req_set_insecure(c, 1); break;
        case 'c':
            if (req_set_ca(c, optarg, NULL)) {
                fprintf(stderr, "cannot load CA bundle %s\n", optarg);
                return 2;
            }
            break;
        case 't': req_set_timeout_ms(c, 0, atoi(optarg) * 1000); break;
        case 'L': req_set_redirects(c, atoi(optarg)); break;
        case 'v': verbose = 1; break;
        default: usage(); return opt == 'h' ? 0 : 2;
        }
    }
    if (optind != argc - 1) {
        usage();
        return 2;
    }
    hdrs[nh] = NULL;
    q.url = argv[optind];
    q.headers = hdrs;
    if (data) {
        q.body = data;
        q.body_len = data_len;
        if (!q.method) q.method = "POST";
        q.content_type = "application/x-www-form-urlencoded";
    }

    r = req_send(c, &q);
    if (r.err) {
        fprintf(stderr, "error: %s\n", req_err_str(r.err));
        rc = 1;
    } else {
        if (verbose) fprintf(stderr, "* %s (%d redirect%s)\n", r.url, r.redirects, r.redirects == 1 ? "" : "s");
        if (show_headers) fwrite(r.headers, 1, r.headers_len, stdout);
        fwrite(r.body, 1, r.body_len, stdout);
        if (r.status >= 400) rc = 22; /* like curl --fail */
    }
    req_response_free(&r);
    req_client_free(c);
    free(data);
    return rc;
}
