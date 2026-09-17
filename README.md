# libreq

[![CI](https://github.com/Flatpack-sonc/libreq/actions/workflows/ci.yml/badge.svg)](https://github.com/Flatpack-sonc/libreq/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

C11 **HTTP/1.1** client for REST. No libcurl, no HTTP/2, no cookies.

```c
#include <req.h>

req_client *c = req_client_new();
req_response r = req_get(c, "https://example.com/");
if (r.err) fprintf(stderr, "%s\n", req_err_str(r.err));
else printf("%d\n%.*s\n", r.status, (int)r.body_len, r.body);
req_response_free(&r);
req_client_free(c);
```

Keep-alive pool, connect/IO timeouts, retries on idempotent methods, limited redirects, TLS via OpenSSL (certificate + hostname verify). CRLF in URLs and extra headers is rejected.

```bash
git clone https://github.com/Flatpack-sonc/libreq.git
cd libreq
make test SANITIZE=1
```

Needs OpenSSL 1.1+/3. Vendor: `include/req.h` + `src/*.c` with `-DREQ_USE_OPENSSL -lssl -lcrypto`.

The client is not thread-safe.

MIT. See [LICENSE](LICENSE).
