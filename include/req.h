#ifndef REQ_H
#define REQ_H

/*
 * libreq — HTTP/1.1 client (REST).
 *
 *   - Keep-alive pool, timeouts, retries on idempotent methods
 *   - TLS via OpenSSL (peer verify + hostname by default)
 *   - No HTTP/2, cookies, FTP, or proxy
 *
 * Client is not thread-safe. Responses own malloc'd buffers; call req_response_free.
 */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define REQ_VERSION "1.0.0"

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
    REQ_ERR_OVERFLOW = 8,
    REQ_ERR_REJECT = 9, /* CRLF / invalid header */
    REQ_ERR_OOM = 10,
    REQ_ERR_CLOSED = 11
} req_err;

typedef struct req_client req_client;

typedef struct req_response {
    int status;
    char *body;
    size_t body_len;
    char *headers; /* raw header block including status line, NUL-terminated */
    size_t headers_len;
    req_err err;
} req_response;

typedef struct req_request {
    const char *method;       /* NULL => GET */
    const char *url;
    const void *body;
    size_t body_len;
    const char *content_type; /* for POST/PUT/PATCH */
    const char **headers;     /* optional extra "Name: value", NULL-terminated */
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

REQ_API req_response req_send(req_client *c, const req_request *r);
REQ_API req_response req_get(req_client *c, const char *url);
REQ_API req_response req_head(req_client *c, const char *url);
REQ_API req_response req_delete(req_client *c, const char *url);
REQ_API req_response req_post(req_client *c, const char *url, const void *body, size_t len,
                              const char *content_type);
REQ_API req_response req_put(req_client *c, const char *url, const void *body, size_t len,
                             const char *content_type);

REQ_API void req_response_free(req_response *r);
REQ_API const char *req_header_get(const req_response *r, const char *name);

#ifdef __cplusplus
}
#endif

#endif /* REQ_H */
