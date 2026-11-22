/* ===----------------------------------------------------------------------===
 * Copyright (c) 2026 the grpc-mojo contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 * ===----------------------------------------------------------------------===
 *
 * Thin C wrapper over libssl for mojo-tls.
 *
 * Exists for one structural reason: OpenSSL's server-side ALPN selection
 * happens through a C callback, which Mojo cannot provide. The callback
 * lives here (selecting from a protocol list stored on the context), and
 * while we are at it the handful of context/handshake/read/write entry
 * points are flattened into a plain function surface that is pleasant to
 * call through dlopen/dlsym.
 *
 * Conventions: every function is prefixed mts_; handles are opaque
 * pointers returned as void*; functions returning int use >= 0 for
 * success and negative values for failure (read/write return the
 * negated SSL_get_error class so the caller can distinguish clean TLS
 * EOF, syscall errors, and protocol errors).
 */

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#ifdef __linux__
#include <signal.h>
#include <time.h>
#endif

typedef struct mts_server_name {
    char *host;
    SSL_CTX *ctx;
    struct mts_server_name *next;
} mts_server_name;

/* The servername callback reads names on handshake threads while add and
 * remove may run on another thread, so names_lock guards the list. */
typedef struct {
    SSL_CTX *ctx;
    unsigned char alpn_wire[256];
    int alpn_len;
    atomic_int refs;
    pthread_mutex_t names_lock;
    mts_server_name *names;
    int names_installed;
    /* NUL-separated host names that negotiate no ALPN, under names_lock. */
    char *raw_names;
    int raw_names_len;
    /* NUL-separated host names that negotiate only h2, under names_lock. */
    char *h2_names;
    int h2_names_len;
} mts_ctx;

typedef struct {
    SSL *ssl;
    mts_ctx *config;
} mts_ssl;

#define MTS_MAX_PEER_CERT_DER (1024 * 1024)
#define MTS_MAX_PEER_NAME 4096
#define MTS_MAX_PEER_SAN_COUNT 256
#define MTS_MAX_PEER_SAN_BYTES (64 * 1024)
#define MTS_MAX_PEER_SAN_VALUE 4096

#define MTS_SAN_DNS 1
#define MTS_SAN_URI 2
#define MTS_SAN_EMAIL 3
#define MTS_SAN_IP 4

/* A read that met the end of the TCP stream with no close_notify. It is not
 * a clean EOF, since the peer's data before it may be cut off. OpenSSL 3
 * reports it as SSL_ERROR_SSL with SSL_R_UNEXPECTED_EOF_WHILE_READING. The
 * value lies outside SSL_get_error's classes. */
#define MTS_PEER_CLOSED 100

/* OpenSSL's socket BIO uses write(2), so a peer reset can raise SIGPIPE on
 * Linux before libssl returns SSL_ERROR_SYSCALL. Block the signal only on
 * the calling thread and consume it only when this operation created it.
 * This preserves the application's process-wide signal policy. */
#ifdef __linux__
typedef struct {
    sigset_t blocked;
    sigset_t previous_mask;
    int active;
    int was_pending;
} mts_sigpipe_guard;

static int mts_sigpipe_guard_begin(mts_sigpipe_guard *guard) {
    memset(guard, 0, sizeof(*guard));
    sigemptyset(&guard->blocked);
    sigaddset(&guard->blocked, SIGPIPE);

    int error = pthread_sigmask(SIG_BLOCK, &guard->blocked,
                                &guard->previous_mask);
    if (error != 0) {
        errno = error;
        return -1;
    }
    guard->active = 1;

    sigset_t pending;
    if (sigpending(&pending) != 0) {
        error = errno;
        pthread_sigmask(SIG_SETMASK, &guard->previous_mask, NULL);
        guard->active = 0;
        errno = error;
        return -1;
    }
    guard->was_pending = sigismember(&pending, SIGPIPE) == 1;
    return 0;
}

static void mts_sigpipe_guard_end(mts_sigpipe_guard *guard, int io_errno) {
    if (!guard->active) return;

    if (io_errno == EPIPE && !guard->was_pending) {
        struct timespec no_wait = {0, 0};
        (void)sigtimedwait(&guard->blocked, NULL, &no_wait);
    }
    (void)pthread_sigmask(SIG_SETMASK, &guard->previous_mask, NULL);
    guard->active = 0;
    errno = io_errno;
}
#else
typedef struct {
    int unused;
} mts_sigpipe_guard;

static int mts_sigpipe_guard_begin(mts_sigpipe_guard *guard) {
    (void)guard;
    return 0;
}

static void mts_sigpipe_guard_end(mts_sigpipe_guard *guard, int io_errno) {
    (void)guard;
    errno = io_errno;
}
#endif

/* Server-side ALPN selection: pick the first protocol from our stored
 * list that the client offered. Fatal alert on no overlap, per RFC 7301. */
static int mts_name_listed(mts_ctx *c, char *const *names, const int *len,
                           const char *host) {
    if (!host || !host[0]) return 0;
    int found = 0;
    pthread_mutex_lock(&c->names_lock);
    for (int at = 0; at < *len && !found;) {
        const char *name = *names + at;
        found = strcasecmp(name, host) == 0;
        at += (int)strlen(name) + 1;
    }
    pthread_mutex_unlock(&c->names_lock);
    return found;
}

static int mts_raw_name(mts_ctx *c, const char *host) {
    return mts_name_listed(c, &c->raw_names, &c->raw_names_len, host);
}

static int mts_h2_name(mts_ctx *c, const char *host) {
    return mts_name_listed(c, &c->h2_names, &c->h2_names_len, host);
}

static int mts_alpn_select(SSL *ssl, const unsigned char **out,
                           unsigned char *outlen, const unsigned char *in,
                           unsigned int inlen, void *arg) {
    mts_ctx *c = (mts_ctx *)arg;
    if (c->alpn_len == 0) return SSL_TLSEXT_ERR_NOACK;
    const char *host = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (mts_raw_name(c, host)) return SSL_TLSEXT_ERR_NOACK;
    if (mts_h2_name(c, host)) {
        static const unsigned char h2_wire[] = {2, 'h', '2'};
        if (SSL_select_next_proto((unsigned char **)out, outlen, h2_wire,
                                  sizeof(h2_wire), in,
                                  inlen) == OPENSSL_NPN_NEGOTIATED)
            return SSL_TLSEXT_ERR_OK;
        return SSL_TLSEXT_ERR_NOACK;
    }
    if (SSL_select_next_proto((unsigned char **)out, outlen, c->alpn_wire,
                              (unsigned int)c->alpn_len, in,
                              inlen) == OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_OK;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

void *mts_ctx_new_client(void) {
    mts_ctx *c = calloc(1, sizeof(mts_ctx));
    if (!c) return NULL;
    c->ctx = SSL_CTX_new(TLS_client_method());
    if (!c->ctx) {
        free(c);
        return NULL;
    }
    atomic_init(&c->refs, 1);
    pthread_mutex_init(&c->names_lock, NULL);
    SSL_CTX_set_min_proto_version(c->ctx, TLS1_2_VERSION);
    /* Resume with a ticket only. Early application data stays off. */
    SSL_CTX_set_session_cache_mode(c->ctx, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_set_max_early_data(c->ctx, 0);
    return c;
}

/* Library callers cannot answer an interactive PEM password prompt. Refuse
 * encrypted keys now. A future passphrase API can replace this callback with
 * one that copies an explicit caller-owned secret. */
static int mts_reject_password(char *buf, int size, int rwflag,
                               void *userdata) {
    (void)rwflag;
    (void)userdata;
    if (buf && size > 0) buf[0] = '\0';
    return 0;
}

void *mts_ctx_new_server(const char *cert_chain_pem, const char *key_pem) {
    mts_ctx *c = calloc(1, sizeof(mts_ctx));
    if (!c) return NULL;
    c->ctx = SSL_CTX_new(TLS_server_method());
    if (!c->ctx) {
        free(c);
        return NULL;
    }
    atomic_init(&c->refs, 1);
    pthread_mutex_init(&c->names_lock, NULL);
    SSL_CTX_set_min_proto_version(c->ctx, TLS1_2_VERSION);
    SSL_CTX_set_session_cache_mode(c->ctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_max_early_data(c->ctx, 0);
    SSL_CTX_set_default_passwd_cb(c->ctx, mts_reject_password);
    SSL_CTX_set_default_passwd_cb_userdata(c->ctx, NULL);
    /* OpenSSL refuses to cache or resume server sessions without this. */
    {
        static const unsigned char sid_ctx[] = "mojo-tls";
        if (SSL_CTX_set_session_id_context(
                c->ctx, sid_ctx, (unsigned int)(sizeof(sid_ctx) - 1)) != 1) {
            SSL_CTX_free(c->ctx);
            free(c);
            return NULL;
        }
    }
    if (SSL_CTX_use_certificate_chain_file(c->ctx, cert_chain_pem) != 1 ||
        SSL_CTX_use_PrivateKey_file(c->ctx, key_pem, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(c->ctx) != 1) {
        SSL_CTX_free(c->ctx);
        free(c);
        return NULL;
    }
    return c;
}

int mts_ctx_load_identity(void *p, const char *cert_chain_pem,
                          const char *key_pem) {
    mts_ctx *c = (mts_ctx *)p;
    ERR_clear_error();
    SSL_CTX_set_default_passwd_cb(c->ctx, mts_reject_password);
    SSL_CTX_set_default_passwd_cb_userdata(c->ctx, NULL);
    if (SSL_CTX_use_certificate_chain_file(c->ctx, cert_chain_pem) != 1)
        return -1;
    if (SSL_CTX_use_PrivateKey_file(c->ctx, key_pem, SSL_FILETYPE_PEM) != 1)
        return -1;
    if (SSL_CTX_check_private_key(c->ctx) != 1) return -1;
    ERR_clear_error();
    return 0;
}

int mts_ctx_load_ca(void *p, const char *ca_pem_path) {
    return SSL_CTX_load_verify_locations(((mts_ctx *)p)->ctx, ca_pem_path,
                                         NULL) == 1
               ? 0
               : -1;
}

int mts_ctx_require_client_cert(void *p, const char *ca_pem_path) {
    mts_ctx *c = (mts_ctx *)p;
    ERR_clear_error();
    if (SSL_CTX_load_verify_locations(c->ctx, ca_pem_path, NULL) != 1)
        return -1;

    STACK_OF(X509_NAME) *ca_names = SSL_load_client_CA_file(ca_pem_path);
    if (!ca_names) return -1;
    if (X509_VERIFY_PARAM_set_flags(SSL_CTX_get0_param(c->ctx),
                                    X509_V_FLAG_X509_STRICT) != 1) {
        sk_X509_NAME_pop_free(ca_names, X509_NAME_free);
        return -1;
    }

    /* SSL_CTX takes ownership of the advertised acceptable CA names. */
    SSL_CTX_set_client_CA_list(c->ctx, ca_names);
    SSL_CTX_set_verify(c->ctx,
                       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       NULL);
    ERR_clear_error();
    return 0;
}

int mts_ctx_load_default_ca(void *p) {
    return SSL_CTX_set_default_verify_paths(((mts_ctx *)p)->ctx) == 1 ? 0 : -1;
}

void mts_ctx_set_verify(void *p, int enabled) {
    SSL_CTX *ctx = ((mts_ctx *)p)->ctx;
    SSL_CTX_set_verify(ctx, enabled ? SSL_VERIFY_PEER : SSL_VERIFY_NONE,
                       NULL);
    if (enabled) {
        /* Match modern CPython (3.13+): strict X.509 checks, so a CA
         * without the proper basicConstraints/keyUsage extensions is
         * rejected the same way the reference implementation rejects
         * it. */
        X509_VERIFY_PARAM_set_flags(SSL_CTX_get0_param(ctx),
                                    X509_V_FLAG_X509_STRICT);
    }
}

/* wire is the ALPN wire format: length-prefixed protocol names, e.g.
 * "\x02h2\x08http/1.1". Configures both directions: the client offer and
 * the server selection callback. */
int mts_ctx_set_alpn(void *p, const unsigned char *wire, int len) {
    mts_ctx *c = (mts_ctx *)p;
    if (len <= 0 || len > (int)sizeof(c->alpn_wire)) return -1;
    memcpy(c->alpn_wire, wire, (size_t)len);
    c->alpn_len = len;
    /* Note: this call returns 0 on success, unlike most of libssl. */
    if (SSL_CTX_set_alpn_protos(c->ctx, wire, (unsigned int)len) != 0)
        return -1;
    SSL_CTX_set_alpn_select_cb(c->ctx, mts_alpn_select, c);
    return 0;
}

static void mts_server_name_free(mts_server_name *n) {
    SSL_CTX_free(n->ctx);
    free(n->host);
    free(n);
}

static void mts_ctx_release(mts_ctx *c) {
    if (!c) return;
    if (atomic_fetch_sub_explicit(&c->refs, 1, memory_order_acq_rel) != 1)
        return;
    while (c->names) {
        mts_server_name *next = c->names->next;
        mts_server_name_free(c->names);
        c->names = next;
    }
    free(c->raw_names);
    free(c->h2_names);
    pthread_mutex_destroy(&c->names_lock);
    SSL_CTX_free(c->ctx);
    free(c);
}

/* SSL_set_SSL_CTX takes its own reference on the child, so a handshake keeps
 * a replaced or removed child alive. Sessions and tickets stay on the parent
 * because SSL_set_SSL_CTX does not change the session context. No match
 * keeps the parent's default certificate. */
static int mts_servername_select(SSL *ssl, int *alert, void *arg) {
    (void)alert;
    mts_ctx *c = (mts_ctx *)arg;
    const char *host = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (!host || !host[0]) return SSL_TLSEXT_ERR_NOACK;
    int matched = 0;
    pthread_mutex_lock(&c->names_lock);
    for (mts_server_name *n = c->names; n; n = n->next) {
        if (strcasecmp(n->host, host) == 0) {
            matched = SSL_set_SSL_CTX(ssl, n->ctx) != NULL;
            break;
        }
    }
    pthread_mutex_unlock(&c->names_lock);
    return matched ? SSL_TLSEXT_ERR_OK : SSL_TLSEXT_ERR_NOACK;
}

static int mts_ctx_use_pem_identity(SSL_CTX *ctx, const unsigned char *chain,
                                    int chain_len, const unsigned char *key,
                                    int key_len) {
    BIO *bio = BIO_new_mem_buf(chain, chain_len);
    if (!bio) return -1;
    X509 *leaf = PEM_read_bio_X509(bio, NULL, mts_reject_password, NULL);
    int rc = leaf && SSL_CTX_use_certificate(ctx, leaf) == 1 ? 0 : -1;
    X509_free(leaf);
    while (rc == 0) {
        X509 *ca = PEM_read_bio_X509(bio, NULL, mts_reject_password, NULL);
        if (!ca) {
            unsigned long e = ERR_peek_last_error();
            if (ERR_GET_LIB(e) == ERR_LIB_PEM &&
                ERR_GET_REASON(e) == PEM_R_NO_START_LINE)
                ERR_clear_error();
            else
                rc = -1;
            break;
        }
        if (SSL_CTX_add0_chain_cert(ctx, ca) != 1) {
            X509_free(ca);
            rc = -1;
        }
    }
    BIO_free(bio);
    if (rc != 0) return -1;

    bio = BIO_new_mem_buf(key, key_len);
    if (!bio) return -1;
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, mts_reject_password,
                                             NULL);
    BIO_free(bio);
    if (!pkey) return -1;
    rc = SSL_CTX_use_PrivateKey(ctx, pkey) == 1 ? 0 : -1;
    EVP_PKEY_free(pkey);
    if (rc != 0 || SSL_CTX_check_private_key(ctx) != 1) return -1;
    return 0;
}

/* The child copies the parent's protocol floor, session id context, verify
 * mode, verify parameters, trust store, and client CA list. Its ALPN
 * callback reads the parent's protocol list, so a later mts_ctx_set_alpn
 * applies to every name. */
static SSL_CTX *mts_server_name_ctx(mts_ctx *c, const unsigned char *chain,
                                    int chain_len, const unsigned char *key,
                                    int key_len) {
    static const unsigned char sid_ctx[] = "mojo-tls";
    SSL_CTX *parent = c->ctx;
    SSL_CTX *child = SSL_CTX_new(TLS_server_method());
    if (!child) return NULL;
    STACK_OF(X509_NAME) *ca_names = SSL_CTX_get_client_CA_list(parent);
    SSL_CTX_set_min_proto_version(child,
                                  SSL_CTX_get_min_proto_version(parent));
    SSL_CTX_set_max_early_data(child, 0);
    SSL_CTX_set_alpn_select_cb(child, mts_alpn_select, c);
    SSL_CTX_set_verify(child, SSL_CTX_get_verify_mode(parent),
                       SSL_CTX_get_verify_callback(parent));
    if (SSL_CTX_set_session_id_context(
            child, sid_ctx, (unsigned int)(sizeof(sid_ctx) - 1)) != 1 ||
        X509_VERIFY_PARAM_set1(SSL_CTX_get0_param(child),
                               SSL_CTX_get0_param(parent)) != 1) {
        SSL_CTX_free(child);
        return NULL;
    }
    SSL_CTX_set1_cert_store(child, SSL_CTX_get_cert_store(parent));
    if (ca_names && sk_X509_NAME_num(ca_names) > 0) {
        STACK_OF(X509_NAME) *copy = SSL_dup_CA_list(ca_names);
        if (!copy) {
            SSL_CTX_free(child);
            return NULL;
        }
        SSL_CTX_set_client_CA_list(child, copy);
    }
    if (mts_ctx_use_pem_identity(child, chain, chain_len, key, key_len) != 0) {
        SSL_CTX_free(child);
        return NULL;
    }
    return child;
}

/* Adds or replaces the certificate served when the client's SNI matches host
 * (ASCII case-insensitive, exact). Returns 0 or -1 with the error queued. */
int mts_ctx_add_server_name(void *server_ctx, const char *host,
                            const unsigned char *chain_pem, int chain_len,
                            const unsigned char *key_pem, int key_len) {
    mts_ctx *c = (mts_ctx *)server_ctx;
    ERR_clear_error();
    if (!c || !host || !host[0] || !chain_pem || chain_len <= 0 || !key_pem ||
        key_len <= 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return -1;
    }
    SSL_CTX *child = mts_server_name_ctx(c, chain_pem, chain_len, key_pem,
                                         key_len);
    if (!child) return -1;

    pthread_mutex_lock(&c->names_lock);
    mts_server_name *n = c->names;
    while (n && strcasecmp(n->host, host) != 0) n = n->next;
    if (n) {
        SSL_CTX_free(n->ctx);
        n->ctx = child;
    } else {
        n = calloc(1, sizeof(mts_server_name));
        char *copy = strdup(host);
        if (!n || !copy) {
            pthread_mutex_unlock(&c->names_lock);
            free(n);
            free(copy);
            SSL_CTX_free(child);
            ERR_raise(ERR_LIB_SSL, ERR_R_MALLOC_FAILURE);
            return -1;
        }
        n->host = copy;
        n->ctx = child;
        n->next = c->names;
        c->names = n;
    }
    if (!c->names_installed) {
        SSL_CTX_set_tlsext_servername_callback(c->ctx, mts_servername_select);
        SSL_CTX_set_tlsext_servername_arg(c->ctx, c);
        c->names_installed = 1;
    }
    pthread_mutex_unlock(&c->names_lock);
    ERR_clear_error();
    return 0;
}

static int mts_set_names(mts_ctx *c, char **slot, int *slot_len,
                         const char *names, int len) {
    if (!c || len < 0 || (len > 0 && (!names || names[len - 1] != 0)))
        return -1;
    char *copy = NULL;
    if (len > 0) {
        copy = malloc((size_t)len);
        if (!copy) return -1;
        memcpy(copy, names, (size_t)len);
    }
    pthread_mutex_lock(&c->names_lock);
    char *old = *slot;
    *slot = copy;
    *slot_len = len;
    pthread_mutex_unlock(&c->names_lock);
    free(old);
    return 0;
}

/* Replaces the host names whose handshakes negotiate no ALPN. names holds
 * len bytes of NUL-terminated names back to back. Returns 0 or -1. */
int mts_ctx_set_raw_names(void *server_ctx, const char *names, int len) {
    mts_ctx *c = (mts_ctx *)server_ctx;
    if (!c) return -1;
    return mts_set_names(c, &c->raw_names, &c->raw_names_len, names, len);
}

/* Replaces the host names whose handshakes agree to h2 when the client
 * offers it and to nothing otherwise, in the format of
 * mts_ctx_set_raw_names. Returns 0 or -1. */
int mts_ctx_set_h2_names(void *server_ctx, const char *names, int len) {
    mts_ctx *c = (mts_ctx *)server_ctx;
    if (!c) return -1;
    return mts_set_names(c, &c->h2_names, &c->h2_names_len, names, len);
}

/* Returns 0 when host was removed and 1 when it was not configured. */
int mts_ctx_remove_server_name(void *server_ctx, const char *host) {
    mts_ctx *c = (mts_ctx *)server_ctx;
    ERR_clear_error();
    if (!c || !host) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return -1;
    }
    mts_server_name *removed = NULL;
    pthread_mutex_lock(&c->names_lock);
    for (mts_server_name **link = &c->names; *link; link = &(*link)->next) {
        if (strcasecmp((*link)->host, host) == 0) {
            removed = *link;
            *link = removed->next;
            break;
        }
    }
    pthread_mutex_unlock(&c->names_lock);
    if (!removed) return 1;
    mts_server_name_free(removed);
    return 0;
}

void mts_ctx_free(void *p) {
    mts_ctx *c = (mts_ctx *)p;
    mts_ctx_release(c);
}

void *mts_ssl_new(void *p, int fd) {
    mts_ctx *c = (mts_ctx *)p;
    mts_ssl *s = calloc(1, sizeof(mts_ssl));
    if (!s) return NULL;
    s->ssl = SSL_new(c->ctx);
    if (!s->ssl) {
        free(s);
        return NULL;
    }
    s->config = c;
    atomic_fetch_add_explicit(&c->refs, 1, memory_order_relaxed);
    SSL_set_mode(s->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE |
                             SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    if (SSL_set_fd(s->ssl, fd) != 1) {
        SSL_free(s->ssl);
        mts_ctx_release(c);
        free(s);
        return NULL;
    }
    return s;
}

/* CPython's default host flags. A whole-label wildcard ("*.example.com")
 * matches one label. A partial wildcard ("www*.example.com") does not.
 * The subject CN is a fallback only when the leaf has no DNS SAN:
 * ALWAYS_CHECK_SUBJECT and NEVER_CHECK_SUBJECT stay off. SSL_set1_host
 * leaves these flags at zero, so both the handshake and the ticket name
 * check set them explicitly. */
#define MTS_HOST_FLAGS X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS

/* sni also enables RFC 6125 hostname verification against the peer
 * certificate; pass an empty string to skip both. This is separate from
 * SSL_connect because a nonblocking handshake configures the name once. */
int mts_ssl_set_connect_name(void *s, const char *sni) {
    SSL *ssl = ((mts_ssl *)s)->ssl;
    if (sni && sni[0]) {
        struct in_addr v4;
        struct in6_addr v6;
        X509_VERIFY_PARAM *param = SSL_get0_param(ssl);
        if (!param) return -1;
        if (inet_pton(AF_INET, sni, &v4) == 1 ||
            inet_pton(AF_INET6, sni, &v6) == 1) {
            /* RFC 6066: SNI is a DNS name. Verify IP SANs instead. */
            if (X509_VERIFY_PARAM_set1_ip_asc(param, sni) != 1) return -1;
            return 0;
        }
        if (SSL_set_tlsext_host_name(ssl, sni) != 1) return -1;
        if (SSL_set1_host(ssl, sni) != 1) return -1;
        /* After SSL_set1_host, which does not install host flags. */
        X509_VERIFY_PARAM_set_hostflags(param, MTS_HOST_FLAGS);
    }
    return 0;
}

/* SSL_get_error requires the thread error queue to be empty before the I/O
 * call it classifies. Handshake calls return 0 on completion or the negated
 * error class. WANT_READ (-2) and WANT_WRITE (-3) are progress states. */
int mts_ssl_connect(void *s) {
    SSL *ssl = ((mts_ssl *)s)->ssl;
    mts_sigpipe_guard guard;
    if (mts_sigpipe_guard_begin(&guard) != 0) return -SSL_ERROR_SYSCALL;
    ERR_clear_error();
    errno = 0;
    int n = SSL_connect(ssl);
    int io_errno = errno;
    int result = n == 1 ? 0 : -SSL_get_error(ssl, n);
    mts_sigpipe_guard_end(&guard, io_errno);
    return result;
}

/* TLS 1.3 can report SSL_connect success before a post-handshake alert
 * (rejected client certificate) is processed. Peek without blocking. When
 * this session presented a client certificate on a blocking socket, wait
 * briefly for POLLIN so that alert is not missed. */
int mts_ssl_confirm_connect(void *s) {
    SSL *ssl = ((mts_ssl *)s)->ssl;
    int fd = SSL_get_fd(ssl);
    if (fd < 0) return -SSL_ERROR_SYSCALL;

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -SSL_ERROR_SYSCALL;
    int blocking = (flags & O_NONBLOCK) == 0;
    int wait_for_alert = blocking && SSL_get_certificate(ssl) != NULL;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return -SSL_ERROR_SYSCALL;

    unsigned char buf[1];
    int result = 0;
    int attempts = wait_for_alert ? 2 : 1;
    int i;
    for (i = 0; i < attempts; i++) {
        if (i == 1) {
            struct pollfd pfd;
            memset(&pfd, 0, sizeof(pfd));
            pfd.fd = fd;
            pfd.events = POLLIN | POLLERR | POLLHUP;
            int pr = poll(&pfd, 1, 50);
            if (pr <= 0) break;
        }
        mts_sigpipe_guard guard;
        if (mts_sigpipe_guard_begin(&guard) != 0) {
            result = -SSL_ERROR_SYSCALL;
            break;
        }
        ERR_clear_error();
        errno = 0;
        int n = SSL_peek(ssl, buf, 1);
        int io_errno = errno;
        if (n > 0) {
            result = 0;
            mts_sigpipe_guard_end(&guard, io_errno);
            break;
        }
        int error = SSL_get_error(ssl, n);
        mts_sigpipe_guard_end(&guard, io_errno);
        if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
            result = 0;
            continue;
        }
        /* close_notify after a completed handshake is a clean EOF; the next
         * SSL_read reports it again. Only a fatal alert rejects the
         * session. */
        if (error == SSL_ERROR_ZERO_RETURN) {
            result = 0;
            break;
        }
        result = -error;
        break;
    }
    (void)fcntl(fd, F_SETFL, flags);
    return result;
}

int mts_ssl_accept(void *s) {
    SSL *ssl = ((mts_ssl *)s)->ssl;
    mts_sigpipe_guard guard;
    if (mts_sigpipe_guard_begin(&guard) != 0) return -SSL_ERROR_SYSCALL;
    ERR_clear_error();
    errno = 0;
    int n = SSL_accept(ssl);
    int io_errno = errno;
    int result = n == 1 ? 0 : -SSL_get_error(ssl, n);
    mts_sigpipe_guard_end(&guard, io_errno);
    return result;
}

static int mts_read_failure(SSL *ssl, int n) {
    int error = SSL_get_error(ssl, n);
    if (error == SSL_ERROR_ZERO_RETURN) return 0;
    if (error != SSL_ERROR_SSL) return -error;
    unsigned long reason = ERR_peek_error();
    if (ERR_GET_LIB(reason) != ERR_LIB_SSL) return -error;
    if (ERR_GET_REASON(reason) != SSL_R_UNEXPECTED_EOF_WHILE_READING) {
        return -error;
    }
    return -MTS_PEER_CLOSED;
}

/* Returns bytes read (> 0), 0 on clean TLS EOF (close_notify),
 * -MTS_PEER_CLOSED on an end with no close_notify, or the negated
 * SSL_get_error class (< 0). */
int mts_ssl_read(void *s, unsigned char *buf, int len) {
    SSL *ssl = ((mts_ssl *)s)->ssl;
    mts_sigpipe_guard guard;
    if (mts_sigpipe_guard_begin(&guard) != 0) return -SSL_ERROR_SYSCALL;
    ERR_clear_error();
    errno = 0;
    int n = SSL_read(ssl, buf, len);
    int io_errno = errno;
    int result = n > 0 ? n : mts_read_failure(ssl, n);
    mts_sigpipe_guard_end(&guard, io_errno);
    return result;
}

/* Returns bytes written (> 0) or the negated SSL_get_error class. */
int mts_ssl_write(void *s, const unsigned char *buf, int len) {
    SSL *ssl = ((mts_ssl *)s)->ssl;
    mts_sigpipe_guard guard;
    if (mts_sigpipe_guard_begin(&guard) != 0) return -SSL_ERROR_SYSCALL;
    ERR_clear_error();
    errno = 0;
    int n = SSL_write(ssl, buf, len);
    int io_errno = errno;
    int result = n > 0 ? n : -SSL_get_error(ssl, n);
    mts_sigpipe_guard_end(&guard, io_errno);
    return result;
}

int mts_ssl_wants_read(void *s) {
    return SSL_want_read(((mts_ssl *)s)->ssl);
}

int mts_ssl_wants_write(void *s) {
    return SSL_want_write(((mts_ssl *)s)->ssl);
}

/* Copies the negotiated ALPN protocol into buf; returns its length, or 0
 * when nothing was negotiated. */
int mts_ssl_get_alpn(void *s, unsigned char *buf, int cap) {
    SSL *ssl = ((mts_ssl *)s)->ssl;
    const unsigned char *d = NULL;
    unsigned int l = 0;
    SSL_get0_alpn_selected(ssl, &d, &l);
    if (!d || (int)l > cap) return 0;
    memcpy(buf, d, l);
    return (int)l;
}

/* The client's SNI host name, or "" when none was sent. The string is owned
 * by the SSL and lives until mts_ssl_free. */
const char *mts_ssl_server_name(void *s) {
    const char *name =
        SSL_get_servername(((mts_ssl *)s)->ssl, TLSEXT_NAMETYPE_host_name);
    return name ? name : "";
}

int mts_ssl_version(void *s, char *buf, int cap) {
    const char *v = SSL_get_version(((mts_ssl *)s)->ssl);
    int l = (int)strlen(v);
    if (l >= cap) l = cap - 1;
    memcpy(buf, v, (size_t)l);
    buf[l] = 0;
    return l;
}

#define MTS_MAX_SESSION_DER (16 * 1024)

/* Copies a resumable session ticket as DER. Returns the length, 0 when no
 * resumable ticket is available yet, or a negative value on failure.
 * TLS 1.3 tickets often arrive after the handshake, so callers should
 * exchange application data first. Early data is never enabled. */
int mts_ssl_export_session(void *s, unsigned char *out, int cap) {
    SSL_SESSION *sess;
    int needed;
    unsigned char *cursor;
    int written;

    if (!s || !out || cap <= 0 || cap > MTS_MAX_SESSION_DER) return -1;
    ERR_clear_error();
    sess = SSL_get1_session(((mts_ssl *)s)->ssl);
    if (!sess) {
        ERR_clear_error();
        return 0;
    }
    if (!SSL_SESSION_is_resumable(sess)) {
        SSL_SESSION_free(sess);
        ERR_clear_error();
        return 0;
    }
    needed = i2d_SSL_SESSION(sess, NULL);
    if (needed <= 0 || needed > MTS_MAX_SESSION_DER || needed > cap) {
        SSL_SESSION_free(sess);
        return -1;
    }
    cursor = out;
    written = i2d_SSL_SESSION(sess, &cursor);
    SSL_SESSION_free(sess);
    if (written != needed) return -1;
    ERR_clear_error();
    return written;
}

static int mts_name_is_ip_literal(const char *name) {
    struct in_addr ipv4;
    struct in6_addr ipv6;
    return inet_pton(AF_INET, name, &ipv4) == 1 ||
           inet_pton(AF_INET6, name, &ipv6) == 1;
}

/* Same window as OpenSSL's certificate time check: notBefore <= now and
 * notAfter still in the future. A comparison error rejects the ticket. */
static int mts_peer_cert_is_current(const X509 *cert) {
    const ASN1_TIME *not_before = X509_get0_notBefore(cert);
    const ASN1_TIME *not_after = X509_get0_notAfter(cert);
    if (!not_before || !not_after) return 0;
    if (X509_cmp_current_time(not_before) != -1) return 0;
    return X509_cmp_current_time(not_after) == 1;
}

/* Same rules as mts_ssl_set_connect_name. An empty name skips the name
 * check. IP literals match iPAddress SANs and do not use host flags. */
static int mts_peer_cert_matches_name(X509 *cert, const char *name) {
    if (!name || name[0] == '\0') return 1;
    if (mts_name_is_ip_literal(name))
        return X509_check_ip_asc(cert, name, 0) == 1;
    return X509_check_host(cert, name, strlen(name), MTS_HOST_FLAGS, NULL) ==
           1;
}

static int mts_session_peer_ok(SSL_SESSION *sess, const char *name) {
    X509 *peer = SSL_SESSION_get0_peer(sess);
    if (!peer) return 0;
    if (!mts_peer_cert_is_current(peer)) return 0;
    return mts_peer_cert_matches_name(peer, name);
}

/* Installs a previously exported session for the next handshake.
 *
 * Resumption does not run certificate verification again. When this SSL
 * verifies peers, the ticket is installed only if its stored result is
 * X509_V_OK (readable on the SSL after SSL_set_session; this OpenSSL has
 * no session getter), the peer leaf is present and unexpired, and that
 * leaf matches name. Otherwise the ticket is discarded and the caller
 * performs a full handshake. name may be empty or NULL. A ticket does
 * not send 0-RTT application data. Returns 0 when the handshake may
 * proceed, or -1 when the ticket bytes are unusable. */
int mts_ssl_set_session(void *s, const unsigned char *der, int len,
                        const char *name) {
    const unsigned char *cursor;
    SSL_SESSION *sess;
    SSL *ssl;
    int verifying;
    int rc;

    if (!s || !der || len <= 0 || len > MTS_MAX_SESSION_DER) return -1;
    ERR_clear_error();
    cursor = der;
    sess = d2i_SSL_SESSION(NULL, &cursor, (long)len);
    if (!sess) return -1;
    SSL_SESSION_set_max_early_data(sess, 0);

    ssl = ((mts_ssl *)s)->ssl;
    verifying = (SSL_get_verify_mode(ssl) & SSL_VERIFY_PEER) != 0;
    if (verifying && !mts_session_peer_ok(sess, name)) {
        SSL_SESSION_free(sess);
        ERR_clear_error();
        return 0;
    }

    rc = SSL_set_session(ssl, sess);
    if (rc == 1 && verifying && SSL_get_verify_result(ssl) != X509_V_OK) {
        (void)SSL_set_session(ssl, NULL);
        SSL_set_verify_result(ssl, X509_V_OK);
        SSL_SESSION_free(sess);
        ERR_clear_error();
        return 0;
    }
    SSL_SESSION_free(sess);
    return rc == 1 ? 0 : -1;
}

int mts_ssl_session_reused(void *s) {
    return SSL_session_reused(((mts_ssl *)s)->ssl) ? 1 : 0;
}

long mts_ssl_verify_result(void *s) {
    return SSL_get_verify_result(((mts_ssl *)s)->ssl);
}

/* Returns the DER length of the peer's leaf certificate, 0 when the peer did
 * not present one, or a negative value on encoding or size failure. The X509
 * reference stays inside this call. */
int mts_ssl_peer_certificate_der_size(void *s) {
    ERR_clear_error();
    X509 *cert = SSL_get1_peer_certificate(((mts_ssl *)s)->ssl);
    if (!cert) {
        ERR_clear_error();
        return 0;
    }
    int length = i2d_X509(cert, NULL);
    X509_free(cert);
    if (length <= 0) return -1;
    if (length > MTS_MAX_PEER_CERT_DER) {
        ERR_clear_error();
        return -2;
    }
    ERR_clear_error();
    return length;
}

/* Copies the peer leaf certificate into caller-owned storage. No OpenSSL
 * allocation or borrowed pointer crosses this boundary. */
int mts_ssl_peer_certificate_der(void *s, unsigned char *out, int cap) {
    if (!out || cap <= 0 || cap > MTS_MAX_PEER_CERT_DER) return -1;

    ERR_clear_error();
    X509 *cert = SSL_get1_peer_certificate(((mts_ssl *)s)->ssl);
    if (!cert) {
        ERR_clear_error();
        return 0;
    }
    int needed = i2d_X509(cert, NULL);
    if (needed <= 0 || needed > MTS_MAX_PEER_CERT_DER || needed > cap) {
        X509_free(cert);
        return -1;
    }
    unsigned char *cursor = out;
    int written = i2d_X509(cert, &cursor);
    X509_free(cert);
    if (written != needed) return -1;
    ERR_clear_error();
    return written;
}

/* Verification success is meaningful only when a certificate exists and the
 * session was configured to verify the peer. SSL_get_verify_result alone can
 * report X509_V_OK when verification was disabled. */
int mts_ssl_peer_certificate_verified(void *s) {
    SSL *ssl = ((mts_ssl *)s)->ssl;
    X509 *cert = SSL_get1_peer_certificate(ssl);
    if (!cert) return 0;
    X509_free(cert);
    if ((SSL_get_verify_mode(ssl) & SSL_VERIFY_PEER) == 0) return 0;
    return SSL_get_verify_result(ssl) == X509_V_OK ? 1 : 0;
}

/* Copies the certificate name matched by OpenSSL hostname verification. The
 * borrowed SSL_get0_peername pointer never leaves this function. */
int mts_ssl_peer_name(void *s, char *out, int cap) {
    if (!out || cap <= 0 || cap > MTS_MAX_PEER_NAME) return -1;
    if (mts_ssl_peer_certificate_verified(s) != 1) return 0;

    const char *name = SSL_get0_peername(((mts_ssl *)s)->ssl);
    if (!name) return 0;
    size_t length = 0;
    while (length < (size_t)cap && name[length] != '\0') length++;
    if (length == (size_t)cap) return -1;
    memcpy(out, name, length);
    return (int)length;
}

/* Copies supported subject alternative names into caller-owned storage.
 * Each record is a one-byte kind, a two-byte big-endian length, then the
 * value bytes. DNS, URI, and email entries must contain printable ASCII. IP
 * entries use the canonical text returned by inet_ntop. Other GeneralName
 * choices are omitted. The entry count, each value, and the complete copy are
 * bounded. */
int mts_ssl_peer_subject_alt_names(void *s, unsigned char *out, int cap) {
    if (!s || !out || cap <= 0 || cap > MTS_MAX_PEER_SAN_BYTES) return -1;

    ERR_clear_error();
    X509 *cert = SSL_get1_peer_certificate(((mts_ssl *)s)->ssl);
    if (!cert) {
        ERR_clear_error();
        return 0;
    }

    int extension_status = -1;
    GENERAL_NAMES *names = X509_get_ext_d2i(
        cert, NID_subject_alt_name, &extension_status, NULL);
    X509_free(cert);
    if (!names) {
        ERR_clear_error();
        return extension_status == -1 ? 0 : -4;
    }

    int entry_count = sk_GENERAL_NAME_num(names);
    if (entry_count == 0) {
        GENERAL_NAMES_free(names);
        ERR_clear_error();
        return -4;
    }
    if (entry_count < 0 || entry_count > MTS_MAX_PEER_SAN_COUNT) {
        GENERAL_NAMES_free(names);
        ERR_clear_error();
        return -2;
    }

    int written = 0;
    for (int index = 0; index < entry_count; index++) {
        GENERAL_NAME *name = sk_GENERAL_NAME_value(names, index);
        const unsigned char *value = NULL;
        int value_length = 0;
        int kind = 0;
        char ip_text[INET6_ADDRSTRLEN];

        if (!name) {
            GENERAL_NAMES_free(names);
            ERR_clear_error();
            return -4;
        }
        switch (name->type) {
            case GEN_DNS:
                kind = MTS_SAN_DNS;
                value = ASN1_STRING_get0_data(name->d.dNSName);
                value_length = ASN1_STRING_length(name->d.dNSName);
                break;
            case GEN_URI:
                kind = MTS_SAN_URI;
                value = ASN1_STRING_get0_data(name->d.uniformResourceIdentifier);
                value_length = ASN1_STRING_length(
                    name->d.uniformResourceIdentifier);
                break;
            case GEN_EMAIL:
                kind = MTS_SAN_EMAIL;
                value = ASN1_STRING_get0_data(name->d.rfc822Name);
                value_length = ASN1_STRING_length(name->d.rfc822Name);
                break;
            case GEN_IPADD: {
                const unsigned char *address = ASN1_STRING_get0_data(
                    name->d.iPAddress);
                int address_length = ASN1_STRING_length(name->d.iPAddress);
                int family = address_length == 4 ? AF_INET : AF_INET6;
                if ((address_length != 4 && address_length != 16) ||
                    !address || !inet_ntop(family, address, ip_text,
                                           sizeof(ip_text))) {
                    GENERAL_NAMES_free(names);
                    ERR_clear_error();
                    return -4;
                }
                kind = MTS_SAN_IP;
                value = (const unsigned char *)ip_text;
                value_length = (int)strlen(ip_text);
                break;
            }
            default:
                continue;
        }

        if (!value || value_length <= 0 ||
            value_length > MTS_MAX_PEER_SAN_VALUE) {
            GENERAL_NAMES_free(names);
            ERR_clear_error();
            return -4;
        }
        if (kind != MTS_SAN_IP) {
            for (int offset = 0; offset < value_length; offset++) {
                if (value[offset] < 0x20 || value[offset] > 0x7e) {
                    GENERAL_NAMES_free(names);
                    ERR_clear_error();
                    return -4;
                }
            }
        }
        if (written > cap - 3 - value_length ||
            written > MTS_MAX_PEER_SAN_BYTES - 3 - value_length) {
            GENERAL_NAMES_free(names);
            ERR_clear_error();
            return -3;
        }

        out[written++] = (unsigned char)kind;
        out[written++] = (unsigned char)((value_length >> 8) & 0xff);
        out[written++] = (unsigned char)(value_length & 0xff);
        memcpy(out + written, value, (size_t)value_length);
        written += value_length;
    }

    GENERAL_NAMES_free(names);
    ERR_clear_error();
    return written;
}

int mts_ssl_shutdown(void *s) {
    /* TLSStream.close treats shutdown as best-effort, so do not let an
     * ignored teardown error leak into the next session on this thread. */
    mts_sigpipe_guard guard;
    if (mts_sigpipe_guard_begin(&guard) != 0) return -1;
    ERR_clear_error();
    errno = 0;
    int rc = SSL_shutdown(((mts_ssl *)s)->ssl);
    int io_errno = errno;
    ERR_clear_error();
    mts_sigpipe_guard_end(&guard, io_errno);
    return rc;
}

void mts_ssl_free(void *p) {
    mts_ssl *s = (mts_ssl *)p;
    if (!s) return;
    SSL_free(s->ssl);
    mts_ctx_release(s->config);
    free(s);
}

/* Pops one entry from the thread's OpenSSL error queue into buf. */
int mts_last_error(char *buf, int cap) {
    unsigned long e = ERR_get_error();
    if (!e) {
        if (cap > 0) buf[0] = 0;
        return 0;
    }
    ERR_error_string_n(e, buf, (size_t)cap);
    return (int)strlen(buf);
}

/* Certificate issuance for TLS-terminating proxies: a CA kept by the
 * proxy, and a leaf per server name signed by it. Private keys are written
 * mode 0600 and certificates hold the leaf followed by the CA. */

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <unistd.h>

#define MTS_CA_NOT_BEFORE "19750101000000Z"
#define MTS_CA_NOT_AFTER "40960101000000Z"
#define MTS_LEAF_DAYS 397

static int mts_write_key(const char *path, EVP_PKEY *key) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    FILE *f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        return -1;
    }
    int ok = PEM_write_PrivateKey(f, key, NULL, NULL, 0, NULL, NULL);
    return (fclose(f) == 0 && ok == 1) ? 0 : -1;
}

static int mts_write_certs(const char *path, X509 *first, X509 *second) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    int ok = PEM_write_X509(f, first);
    if (ok == 1 && second) ok = PEM_write_X509(f, second);
    return (fclose(f) == 0 && ok == 1) ? 0 : -1;
}

static int mts_add_ext(X509 *cert, X509 *issuer, int nid, const char *value) {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, cert, NULL, NULL, 0);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ext) return -1;
    int ok = X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    return ok == 1 ? 0 : -1;
}

static X509 *mts_cert_new(EVP_PKEY *key, const char *cn, long days) {
    X509 *cert = X509_new();
    if (!cert) return NULL;
    unsigned char serial[16];
    BIGNUM *bn = NULL;
    int ok = X509_set_version(cert, 2) == 1 &&
             RAND_bytes(serial, sizeof serial) == 1;
    if (ok) {
        serial[0] &= 0x7f;
        bn = BN_bin2bn(serial, sizeof serial, NULL);
        ok = bn && BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(cert));
    }
    BN_free(bn);
    ok = ok && X509_gmtime_adj(X509_getm_notBefore(cert), -3600) &&
         X509_gmtime_adj(X509_getm_notAfter(cert), days * 86400L) &&
         X509_set_pubkey(cert, key) == 1 &&
         X509_NAME_add_entry_by_txt(X509_get_subject_name(cert), "CN",
                                    MBSTRING_UTF8, (const unsigned char *)cn,
                                    -1, -1, 0) == 1;
    if (!ok) {
        X509_free(cert);
        return NULL;
    }
    return cert;
}

int mts_ca_new(const char *common_name, const char *cert_path,
               const char *key_path) {
    EVP_PKEY *key = EVP_EC_gen("P-256");
    if (!key) return -1;
    X509 *cert = mts_cert_new(key, common_name, 0);
    int ok = cert &&
             ASN1_TIME_set_string_X509(X509_getm_notBefore(cert), MTS_CA_NOT_BEFORE) == 1 &&
             ASN1_TIME_set_string_X509(X509_getm_notAfter(cert), MTS_CA_NOT_AFTER) == 1 &&
             X509_set_issuer_name(cert, X509_get_subject_name(cert)) == 1 &&
             mts_add_ext(cert, cert, NID_basic_constraints,
                         "critical,CA:TRUE,pathlen:0") == 0 &&
             mts_add_ext(cert, cert, NID_key_usage,
                         "critical,keyCertSign,cRLSign") == 0 &&
             mts_add_ext(cert, cert, NID_subject_key_identifier, "hash") == 0 &&
             X509_sign(cert, key, EVP_sha256()) > 0 &&
             mts_write_key(key_path, key) == 0 &&
             mts_write_certs(cert_path, cert, NULL) == 0;
    X509_free(cert);
    EVP_PKEY_free(key);
    return ok ? 0 : -1;
}

static int mts_is_ip(const char *name) {
    unsigned char buf[16];
    return inet_pton(AF_INET, name, buf) == 1 ||
           inet_pton(AF_INET6, name, buf) == 1;
}

int mts_leaf_issue(const char *ca_cert_path, const char *ca_key_path,
                   const char *server_name, const char *cert_path,
                   const char *key_path) {
    FILE *f = fopen(ca_cert_path, "r");
    if (!f) return -1;
    X509 *ca = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    f = fopen(ca_key_path, "r");
    if (!f) {
        X509_free(ca);
        return -1;
    }
    EVP_PKEY *ca_key = PEM_read_PrivateKey(f, NULL, mts_reject_password, NULL);
    fclose(f);
    EVP_PKEY *key = EVP_EC_gen("P-256");
    X509 *cert = NULL;
    char san[300];
    int ok = ca && ca_key && key &&
             strlen(server_name) < sizeof san - 4;
    if (ok) {
        snprintf(san, sizeof san, "%s:%s", mts_is_ip(server_name) ? "IP" : "DNS",
                 server_name);
        cert = mts_cert_new(key, server_name, MTS_LEAF_DAYS);
    }
    ok = ok && cert &&
         X509_set_issuer_name(cert, X509_get_subject_name(ca)) == 1 &&
         mts_add_ext(cert, ca, NID_basic_constraints, "critical,CA:FALSE") == 0 &&
         mts_add_ext(cert, ca, NID_key_usage, "critical,digitalSignature") == 0 &&
         mts_add_ext(cert, ca, NID_ext_key_usage, "serverAuth") == 0 &&
         mts_add_ext(cert, ca, NID_subject_alt_name, san) == 0 &&
         mts_add_ext(cert, ca, NID_authority_key_identifier, "keyid") == 0 &&
         X509_sign(cert, ca_key, EVP_sha256()) > 0 &&
         mts_write_key(key_path, key) == 0 &&
         mts_write_certs(cert_path, cert, ca) == 0;
    X509_free(cert);
    X509_free(ca);
    EVP_PKEY_free(ca_key);
    EVP_PKEY_free(key);
    return ok ? 0 : -1;
}

/* Ed25519 node identity: a key kept as a PKCS#8 PEM file, mode 0600,
 * created on first use and never replaced, so a node keeps the key its host
 * enrolled with across restarts. */

#define MTS_ED25519_PUBLIC_BYTES 32
#define MTS_ED25519_SIGNATURE_BYTES 64

static EVP_PKEY *mts_ed25519_load(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    EVP_PKEY *key = PEM_read_PrivateKey(f, NULL, mts_reject_password, NULL);
    fclose(f);
    if (key && EVP_PKEY_get_id(key) != EVP_PKEY_ED25519) {
        EVP_PKEY_free(key);
        return NULL;
    }
    return key;
}

static EVP_PKEY *mts_ed25519_create(const char *path) {
    char staged[4096];
    if (snprintf(staged, sizeof staged, "%s.staged", path) >= (int)sizeof staged)
        return NULL;
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    if (key && (mts_write_key(staged, key) != 0 || rename(staged, path) != 0)) {
        EVP_PKEY_free(key);
        return NULL;
    }
    return key;
}

/* Writes the 32-byte public key of the key at `path`, creating it when the
 * file does not exist. An unreadable or foreign key file fails. */
int mts_ed25519_key(const char *path, unsigned char *public_key) {
    EVP_PKEY *key = access(path, F_OK) == 0 ? mts_ed25519_load(path)
                                            : mts_ed25519_create(path);
    size_t len = MTS_ED25519_PUBLIC_BYTES;
    int ok = key && EVP_PKEY_get_raw_public_key(key, public_key, &len) == 1 &&
             len == MTS_ED25519_PUBLIC_BYTES;
    EVP_PKEY_free(key);
    return ok ? 0 : -1;
}

/* Writes the 64-byte Ed25519 signature of `message` under the key at
 * `path`. */
int mts_ed25519_sign(const char *path, const unsigned char *message,
                     int message_len, unsigned char *signature) {
    EVP_PKEY *key = mts_ed25519_load(path);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t len = MTS_ED25519_SIGNATURE_BYTES;
    int ok = key && ctx && message_len >= 0 &&
             EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) == 1 &&
             EVP_DigestSign(ctx, signature, &len, message,
                            (size_t)message_len) == 1 &&
             len == MTS_ED25519_SIGNATURE_BYTES;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return ok ? 0 : -1;
}

/* AES-256-GCM with a 12-byte nonce and a 16-byte tag, the AEAD the content
 * plane seals objects with (python/cp/keyd/envelope.py uses the same), and
 * AES-256-CTR at a byte offset, which encrypts local cache files in place
 * under a key that never leaves the process. */

#define MTS_AES_KEY_BYTES 32
#define MTS_GCM_NONCE_BYTES 12
#define MTS_GCM_TAG_BYTES 16
#define MTS_CTR_BLOCK_BYTES 16

/* Writes `len` ciphertext bytes and then the tag to `out`. */
int mts_aes256gcm_seal(const unsigned char *key, const unsigned char *nonce,
                       const unsigned char *aad, int aad_len,
                       const unsigned char *in, int len, unsigned char *out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int n = 0;
    int ok = ctx && aad_len >= 0 && len >= 0 &&
             EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, MTS_GCM_NONCE_BYTES,
                                 NULL) == 1 &&
             EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) == 1 &&
             (aad_len == 0 ||
              EVP_EncryptUpdate(ctx, NULL, &n, aad, aad_len) == 1) &&
             (len == 0 || EVP_EncryptUpdate(ctx, out, &n, in, len) == 1) &&
             EVP_EncryptFinal_ex(ctx, out + len, &n) == 1 &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, MTS_GCM_TAG_BYTES,
                                 out + len) == 1;
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

/* Opens `len` bytes of ciphertext followed by its tag into `out`; -1 when
 * the tag does not authenticate. */
int mts_aes256gcm_open(const unsigned char *key, const unsigned char *nonce,
                       const unsigned char *aad, int aad_len,
                       const unsigned char *in, int len, unsigned char *out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int n = 0;
    unsigned char tag[MTS_GCM_TAG_BYTES];
    if (len >= 0) memcpy(tag, in + len, MTS_GCM_TAG_BYTES);
    int ok = ctx && aad_len >= 0 && len >= 0 &&
             EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, MTS_GCM_NONCE_BYTES,
                                 NULL) == 1 &&
             EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) == 1 &&
             (aad_len == 0 ||
              EVP_DecryptUpdate(ctx, NULL, &n, aad, aad_len) == 1) &&
             (len == 0 || EVP_DecryptUpdate(ctx, out, &n, in, len) == 1) &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, MTS_GCM_TAG_BYTES,
                                 tag) == 1 &&
             EVP_DecryptFinal_ex(ctx, out + len, &n) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok && len > 0) OPENSSL_cleanse(out, (size_t)len);
    return ok ? 0 : -1;
}

/* XORs `len` bytes of `in` with the AES-256-CTR keystream that starts at
 * byte `offset` of a stream whose first counter block is all zero. */
int mts_aes256ctr_xor(const unsigned char *key, unsigned long long offset,
                      const unsigned char *in, int len, unsigned char *out) {
    unsigned char counter[MTS_CTR_BLOCK_BYTES] = {0};
    unsigned long long block = offset / MTS_CTR_BLOCK_BYTES;
    for (int i = 0; i < 8; i++)
        counter[MTS_CTR_BLOCK_BYTES - 1 - i] = (unsigned char)(block >> (8 * i));
    unsigned char skip[MTS_CTR_BLOCK_BYTES] = {0};
    int skipped = (int)(offset % MTS_CTR_BLOCK_BYTES);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int n = 0;
    int ok = ctx && len >= 0 &&
             EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, counter) == 1 &&
             (skipped == 0 ||
              EVP_EncryptUpdate(ctx, skip, &n, skip, skipped) == 1) &&
             (len == 0 || EVP_EncryptUpdate(ctx, out, &n, in, len) == 1);
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

/* Fills `out` with `len` bytes from the OpenSSL CSPRNG. */
int mts_random_bytes(unsigned char *out, int len) {
    return len >= 0 && RAND_bytes(out, len) == 1 ? 0 : -1;
}
