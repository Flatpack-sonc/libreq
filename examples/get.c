#include "req.h"
#include <stdio.h>

int main(int argc, char **argv) {
    req_client *c;
    req_response r;
    const char *url = argc > 1 ? argv[1] : "https://example.com/";

    c = req_client_new();
    if (!c) return 1;
    r = req_get(c, url);
    if (r.err) {
        fprintf(stderr, "error: %s\n", req_err_str(r.err));
        req_client_free(c);
        return 1;
    }
    printf("%d\n%.*s\n", r.status, (int)r.body_len, r.body ? r.body : "");
    req_response_free(&r);
    req_client_free(c);
    return 0;
}
