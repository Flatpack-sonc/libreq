# Security

TLS verifies the peer certificate and hostname unless `req_set_insecure(c, 1)`.

The client is lexical HTTP/1.1 only: no cookie jar, no HTTP/2, no proxy. URLs and extra headers that contain CR/LF are rejected.

Report TLS or request-smuggling issues privately if you can.
