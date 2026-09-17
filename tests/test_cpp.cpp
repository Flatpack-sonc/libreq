#include "req.h"

int main() {
    req_client *c = req_client_new();
    if (!c) return 1;
    req_client_free(c);
    return req_version()[0] ? 0 : 1;
}
