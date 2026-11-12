# Contributing

- `make test SANITIZE=1` must pass with both gcc and clang (`make CC=clang test SANITIZE=1`).
- New parsing code needs unit tests in `tests/test_unit.c`. Run the fuzzers for a few minutes: `make fuzz CC=clang FUZZ_TIME=300`.
- Behaviour visible over the network needs a case in `tests/test_req.c`.
- Keep the public API in `include/req.h` small. `req_response` is returned by value, so changing a public struct breaks the shared-library ABI and needs a SOVERSION bump.
- TLS stays on OpenSSL. Do not add HTTP/2.
