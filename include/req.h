#ifndef REQ_H
#define REQ_H

/*
 * libreq — HTTP/1.1 client (REST).
 *
 *   - Keep-alive pool with liveness checks, timeouts, retries on idempotent methods
 *   - TLS via OpenSSL (peer + hostname/IP verification by default, ALPN http/1.1)
 *   - Strict response framing (Content-Length / chunked / close-delimited), 1xx skipping
 *   - RFC 9110 redirects; credentials are dropped when a redirect leaves the origin,
 *     and https -> http downgrades are never followed
 *   - Never raises SIGPIPE
 *   - No HTTP/2, cookies, FTP, or proxy
 *
 * A client is not thread-safe; use one client per thread.
 * Responses own malloc'd buffers; call req_response_free.
 */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define REQ_VERSION "1.1.0"
#define REQ_VERSION_MAJOR 1
#define REQ_VERSION_MINOR 1
#define REQ_VERSION_PATCH 0

#if defined(__GNUC__) || defined(__clang__)
#define REQ_API __attribute__((visibility("default")))
#else
#define REQ_API
#endif

typedef enum req_err {
    REQ_OK = 0,
    REQ_ERR_URL = 1,
    REQ_ERR_DNS = 2,
    REQ_ERR_CONNECT = 3,
    REQ_ERR_TLS = 4,
    REQ_ERR_TIMEOUT = 5,
    REQ_ERR_IO = 6,
    REQ_ERR_PARSE = 7,
    REQ_ERR_OVERFLOW = 8, /* response larger than the configured limits */
    REQ_ERR_REJECT = 9,   /* invalid method / header / body in the request */
    REQ_ERR_OOM = 10,
    REQ_ERR_CLOSED = 11,
    REQ_ERR_TLS_VERIFY = 12, /* certificate or hostname verification failed */
    REQ_ERR_REDIRECTS = 13   /* more redirects than req_set_redirects allows */
} req_err;

typedef struct req_client req_client;

typedef struct req_response {
    int status;
    char *body; /* always NUL-terminated (body_len excludes the NUL) on success */
    size_t body_len;
    char *headers; /* raw header block including status line, NUL-terminated */
    size_t headers_len;
    req_err err;
    char *url;     /* final URL after redirects (NUL-terminated), NULL on error */
    int redirects; /* number of redirects followed */
} req_response;

typedef struct req_request {
    const char *method;       /* NULL => GET; must be an RFC 9110 token */
    const char *url;
    const void *body;
    size_t body_len;
    const char *content_type; /* sent when body_len > 0 */
    /* Optional extra "Name: value" lines, NULL-terminated.
     * Host, User-Agent, Accept, Connection and Content-Type replace the defaults.
     * Content-Length and Transfer-Encoding are rejected (the library frames the body).
     * Authorization, Proxy-Authorization and Cookie are dropped on cross-origin redirects. */
    const char **headers;
} req_request;

REQ_API const char *req_version(void);
REQ_API const char *req_err_str(req_err e);

REQ_API req_client *req_client_new(void);
REQ_API void req_client_free(req_client *c);

REQ_API void req_set_timeout_ms(req_client *c, int connect_ms, int io_ms);
REQ_API void req_set_retries(req_client *c, int retries); /* extra attempts; default 2 */
REQ_API void req_set_max_body(req_client *c, size_t bytes); /* default 8 MiB */
REQ_API void req_set_insecure(req_client *c, int insecure); /* 1 = skip TLS verify */
REQ_API void req_set_redirects(req_client *c, int max);     /* default 5; 0 disables */
/* Trust anchors: a PEM bundle and/or a hashed directory (either may be NULL).
 * Replaces the system default store. Returns 0 on success, -1 on error. */
REQ_API int req_set_ca(req_client *c, const char *ca_file, const char *ca_dir);

REQ_API req_response req_send(req_client *c, const req_request *r);
REQ_API req_response req_get(req_client *c, const char *url);
REQ_API req_response req_head(req_client *c, const char *url);
REQ_API req_response req_delete(req_client *c, const char *url);
REQ_API req_response req_post(req_client *c, const char *url, const void *body, size_t len,
                              const char *content_type);
REQ_API req_response req_put(req_client *c, const char *url, const void *body, size_t len,
                             const char *content_type);
REQ_API req_response req_patch(req_client *c, const char *url, const void *body, size_t len,
                               const char *content_type);

REQ_API void req_response_free(req_response *r);

/* Case-insensitive lookup of the first header named `name`.
 * req_header_find returns the value (leading/trailing whitespace removed) and its length;
 * the value is NOT NUL-terminated. req_header_get returns the same pointer, whose value
 * ends at the next "\r\n". Both return NULL if the header is absent. */
REQ_API const char *req_header_find(const req_response *r, const char *name, size_t *len);
REQ_API const char *req_header_get(const req_response *r, const char *name);

#ifdef __cplusplus
}
#endif

#endif /* REQ_H */
