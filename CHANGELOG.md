# Changelog

## 1.1.0

### Security
- Redirects that leave the original origin no longer forward `Authorization`, `Proxy-Authorization` or `Cookie` headers. Before this release, credentials were sent to any host a server redirected to.
- Redirects from https to http are no longer followed.
- Response parsing is stricter, to prevent response smuggling and connection desync. libreq now rejects:
  - conflicting or malformed `Content-Length` values,
  - obs-fold header lines,
  - whitespace before the colon in a header,
  - bare CR,
  - malformed status lines,
  - malformed chunk sizes.

  A response with both `Transfer-Encoding` and `Content-Length`, or with stray bytes after the message, is no longer reused.
- Header names and methods must be RFC 9110 tokens. User-supplied `Content-Length` and `Transfer-Encoding` headers are rejected.
- An IP address in the URL is checked against the certificate's iPAddress SANs, and no SNI is sent for it. `X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS` is set.

### Fixed
- Interim responses (`100 Continue`, `103 Early Hints`) were returned as the final response, which desynchronized the connection. They are now skipped.
- A response with no length, or with a non-chunked `Transfer-Encoding`, was treated as an empty body and the connection was kept. Such a body is now read until the connection closes, and the connection is not reused.
- An `HTTP/1.0` response kept the connection alive unless it said `Connection: close`. It is now kept alive only with `Connection: keep-alive`.
- A pooled connection that the server had closed made the next non-idempotent request fail. Idle connections are now checked before reuse, and a request that couldn't be written is resent on a new connection.
- Writing to a connection the peer had reset could kill the process with SIGPIPE, for both plain TCP and TLS. libreq now uses `MSG_NOSIGNAL`, `SO_NOSIGPIPE` and a custom OpenSSL BIO.
- The `Host` header and redirect URLs for IPv6 literals were missing the `[...]` brackets.
- URLs longer than the internal buffer were silently truncated. They are now rejected.
- Relative `Location` values (`a/../b`, `?q`, `//host/path`) were mishandled. They are now resolved per RFC 3986.
- One unreachable address (often IPv6) no longer uses up the whole connect timeout before the next address is tried. EINTR is handled in `poll`.
- On OpenSSL 3, a TLS peer that closed without `close_notify` failed close-delimited bodies.

### Added
- `req_patch`, `req_set_ca`, `req_header_find`.
- `req_response.url` (the final URL) and `req_response.redirects`.
- `REQ_ERR_TLS_VERIFY` (not retried) and `REQ_ERR_REDIRECTS`.
- Redirects 307/308 keep the method and body. 301/302 after POST, and 303, switch to GET.
- ALPN `http/1.1`, LRU eviction in the pool, close-on-exec sockets.
- Bodies over 16 KiB are written straight from the caller's buffer instead of being copied.
- Tests: unit tests for URLs, RFC 3986 resolution and around 40 response-framing cases; an integration suite with a threaded HTTP, HTTPS and IPv6 server and a generated certificate; libFuzzer harnesses; a gcc/clang/macOS/fuzz CI matrix.
- CMake package config (`find_package(req)`), shared-library support with a SONAME, pkg-config file, `make install`.
- `examples/get` is now a small curl-like CLI.

## 1.0.0

- HTTP/1.1 GET/HEAD/POST/PUT/DELETE, chunked bodies, keep-alive pool
- Timeouts, retries on idempotent methods, limited redirects
- TLS via OpenSSL (verify peer + hostname)
