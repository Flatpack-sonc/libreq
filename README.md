# libreq

[![CI](https://github.com/Flatpack-sonc/libreq/actions/workflows/ci.yml/badge.svg)](https://github.com/Flatpack-sonc/libreq/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A small C11 **HTTP/1.1** client for REST APIs. TLS through OpenSSL. It doesn't use libcurl and doesn't support HTTP/2 or cookies.

```c
#include <req.h>

req_client *c = req_client_new();
req_response r = req_get(c, "https://example.com/");
if (r.err) fprintf(stderr, "%s\n", req_err_str(r.err));
else printf("%d %s\n%.*s\n", r.status, r.url, (int)r.body_len, r.body);
req_response_free(&r);
req_client_free(c);
```

## Features

- **Methods:** GET, HEAD, POST, PUT, PATCH, DELETE, and any other token method through `req_send`.
- **Keep-alive pool:** up to 8 connections per client. Before an idle connection is reused, libreq checks that it is still alive, so a connection the server already closed is never used.
- **Timeouts:** a connect timeout and an I/O timeout. The connect budget is split across the resolved addresses, so one unreachable IPv6 address can't use up the whole timeout.
- **Retries:** idempotent methods are retried on network errors. If a reused connection fails before the request was written, the request is resent once on a new connection, for any method.
- **Redirects:** 301/302/303/307/308 with RFC 3986 relative references (see Security below).
- **TLS:** the certificate chain and hostname or IP address are verified by default. TLS 1.2 is the minimum, ALPN is `http/1.1`, SNI is sent for hostnames only, and `req_set_ca` lets you supply your own trust anchors.
- **Strict response parsing:** see Security below.
- **No SIGPIPE:** the library never raises it, so you don't need `signal(SIGPIPE, SIG_IGN)`.
- **Small public API:** only the `req_*` functions are visible from the library.

## API

| Function | Notes |
|---|---|
| `req_client_new()` / `req_client_free(c)` | One client per thread. A client is not thread-safe. |
| `req_set_timeout_ms(c, connect, io)` | Defaults are 10 s connect and 30 s I/O. The I/O timeout covers a whole request and response. |
| `req_set_retries(c, n)` | Extra attempts for idempotent methods. The default is 2. |
| `req_set_redirects(c, n)` | The default is 5. With 0 the 3xx response is returned as is. Going over the limit returns `REQ_ERR_REDIRECTS`. |
| `req_set_max_body(c, bytes)` | The default is 8 MiB. Larger bodies return `REQ_ERR_OVERFLOW`. |
| `req_set_ca(c, file, dir)` | Replaces the system trust store. |
| `req_set_insecure(c, 1)` | Turns off TLS verification. Only use it for testing. |
| `req_get/head/delete(c, url)` | |
| `req_post/put/patch(c, url, body, len, content_type)` | |
| `req_send(c, &req)` | Full control: method, body and extra headers. |
| `req_header_find(&r, name, &len)` | Case-insensitive lookup that returns a trimmed value and its length. |
| `req_response_free(&r)` | Frees `body`, `headers` and `url`. |

A `req_response` holds `status`, `body` and `body_len` (the body is always NUL-terminated), the raw `headers` block, `err`, the final `url` after redirects, and the number of `redirects` followed.

Extra headers are passed as `"Name: value"` strings. Your `Host`, `User-Agent`, `Accept`, `Connection` or `Content-Type` replaces the default. `Content-Length` and `Transfer-Encoding` are rejected, because the library frames the body itself.

```c
const char *hdrs[] = {"Authorization: Bearer TOKEN", "Accept: application/json", NULL};
req_request q = {0};
q.method = "POST";
q.url = "https://api.example.com/items";
q.body = json;
q.body_len = strlen(json);
q.content_type = "application/json";
q.headers = hdrs;
req_response r = req_send(c, &q);
```

## Security

- **Credentials on redirects:** `Authorization`, `Proxy-Authorization` and `Cookie` are sent only to the origin of the original request. They are dropped when a redirect changes the scheme, host or port.
- **No downgrades:** a redirect from https to http is never followed, and the 3xx response is returned instead. Only `http` and `https` redirect targets are followed.
- **Response smuggling:** responses are rejected when they contain:
  - conflicting `Content-Length` values,
  - obs-fold header lines,
  - whitespace before the colon in a header,
  - an invalid status line or bare CR.

  If a response has both `Transfer-Encoding` and `Content-Length`, it is never reused.
- **Request injection:** CR/LF in URLs, the method, extra headers or the content type is rejected with `REQ_ERR_REJECT`.
- **Over-long URLs:** a URL that is too long is rejected rather than truncated.

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## Building

```bash
make test SANITIZE=1        # unit + integration tests under ASan/UBSan
make fuzz CC=clang          # libFuzzer: URL parser and response parser
cmake -B build && cmake --build build && ctest --test-dir build
```

Requirements: OpenSSL 1.1.1 or 3.x, and a POSIX system (Linux, macOS, the BSDs).

To use it from CMake after `cmake --install`: `find_package(req)` and then `target_link_libraries(app req::req)`. A `libreq.pc` pkg-config file is installed too.

To vendor it, copy `include/req.h` and `src/*`, then compile with `-DREQ_USE_OPENSSL -D_DEFAULT_SOURCE` and link with `-lssl -lcrypto`.

`examples/get.c` is a small curl-like CLI:

```bash
./examples/get -v -i -H 'Accept: application/json' https://api.github.com/
```

MIT. See [LICENSE](LICENSE).
