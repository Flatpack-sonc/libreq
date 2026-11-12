# Security

## Defaults

- TLS verifies the certificate chain and the hostname or IP address. Only `req_set_insecure(c, 1)` turns this off. TLS 1.2 is the minimum version.
- Credentials (`Authorization`, `Proxy-Authorization`, `Cookie`) are never forwarded to a different origin on a redirect, and https to http redirects are never followed.
- Responses are framed strictly (RFC 9112). Ambiguous framing is rejected, or the connection is closed instead of reused.
- CR/LF and other invalid input in URLs, methods and headers is rejected before anything is sent.
- The library never raises SIGPIPE.

There is no cookie jar, no HTTP/2 and no proxy support.

## Reporting

Please report TLS, request-smuggling, header-injection or memory-safety issues privately through GitHub Security Advisories ("Report a vulnerability" on the repository's Security tab) rather than in a public issue.
