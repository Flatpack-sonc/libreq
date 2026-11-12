// The public header must compile cleanly as C++ and link from C++ code.
#include "req.h"

#include <cstring>

int main() {
    req_client *c = req_client_new();
    if (!c) return 1;
    req_set_timeout_ms(c, 1000, 1000);
    req_response r = req_get(c, "not a url");
    int ok = r.err == REQ_ERR_URL && std::strcmp(req_err_str(REQ_ERR_TLS_VERIFY), "unknown") != 0;
    req_response_free(&r);
    req_client_free(c);
    return ok && req_version()[0] ? 0 : 1;
}
