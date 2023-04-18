// This source file is part of the Argon project.
//
// Licensed under the Apache License v2.0

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include <argon/vm/datatype/boolean.h>
#include <argon/vm/datatype/error.h>
#include <argon/vm/datatype/integer.h>
#include <argon/vm/datatype/nil.h>

#include <ssl/ssl.h>

using namespace argon::vm::datatype;
using namespace arlib::ssl;

static bool MinMaxProtoVersion(SSLContext *context, unsigned int opt, bool set_max) {
    long result;

    switch (context->protocol) {
        case SSLProtocol::TLS:
        case SSLProtocol::TLS_CLIENT:
        case SSLProtocol::TLS_SERVER:
            break;
        default:
            ErrorFormat(kSSLError[0], "this context doesn't support modification of highest and lowest version");
            return false;
    }

    switch (opt) {
        case SSL3_VERSION:
        case TLS1_VERSION:
        case TLS1_1_VERSION:
        case TLS1_2_VERSION:
        case TLS1_3_VERSION:
            break;
        default:
            ErrorFormat(kSSLError[0], "unsupported TLS/SSL version 0x%x", opt);
            return false;
    }

    result = set_max ? SSL_CTX_set_max_proto_version(context->ctx, opt) :
             SSL_CTX_set_min_proto_version(context->ctx, opt);

    if (result == 0) {
        ErrorFormat(kSSLError[0], "unsupported protocol version 0x%x", opt);
        return false;
    }

    return true;
}

static bool SetVerifyMode(SSLContext *context, SSLVerify mode) {
    int (*callback)(int, X509_STORE_CTX *);
    int sslmode;

    switch (mode) {
        case SSLVerify::CERT_NONE:
            sslmode = SSL_VERIFY_NONE;
            break;
        case SSLVerify::CERT_OPTIONAL:
            sslmode = SSL_VERIFY_PEER;
            break;
        case SSLVerify::CERT_REQUIRED:
            sslmode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
            break;
        default:
            ErrorFormat(kValueError[0], "invalid value for VerifyMode");
            return false;
    }

    callback = SSL_CTX_get_verify_callback(context->ctx);
    SSL_CTX_set_verify(context->ctx, sslmode, callback);

    context->verify_mode = mode;

    return true;
}

ARGON_FUNCTION(sslcontext_sslcontext, SSLContext,
               "i: protocol",
               nullptr, false, false) {
    return (ArObject *) SSLContextNew((SSLProtocol) ((Integer *) *args)->sint);
}

ARGON_METHOD(sslcontext_load_cadata, load_cadata,
             "",
             "x: cadata, i: filetype", false, false) {
    ArBuffer buffer{};
    auto *self = (SSLContext *) _self;
    BIO *biobuf;
    X509_STORE *store;
    unsigned long err;
    int loaded = 0;

    auto filetype = (int) ((Integer *) args[1])->sint;

    if (!BufferGet(args[0], &buffer, BufferFlags::READ))
        return nullptr;

    if (buffer.length == 0) {
        BufferRelease(&buffer);

        ErrorFormat(kValueError[0], "empty certificate data");

        return nullptr;
    }

    if ((biobuf = BIO_new_mem_buf(buffer.buffer, buffer.length)) == nullptr) {
        BufferRelease(&buffer);

        SSLError();

        return nullptr;
    }

    BufferRelease(&buffer);

    // TODO: UniqueLock lock(ctx->lock);

    store = SSL_CTX_get_cert_store(self->ctx);
    assert(store != nullptr);

    do {
        X509 *cert;

        if (filetype == SSL_FILETYPE_ASN1)
            cert = d2i_X509_bio(biobuf, nullptr);
        else {
            cert = PEM_read_bio_X509(biobuf,
                                     nullptr,
                                     SSL_CTX_get_default_passwd_cb(self->ctx),
                                     SSL_CTX_get_default_passwd_cb_userdata(self->ctx));
        }

        if (cert == nullptr)
            break;

        if (!X509_STORE_add_cert(store, cert)) {
            err = ERR_peek_last_error();
            if (ERR_GET_LIB(err) != ERR_LIB_X509 || ERR_GET_REASON(err) != X509_R_CERT_ALREADY_IN_HASH_TABLE) {
                X509_free(cert);
                break;
            }

            ERR_clear_error();
        }

        X509_free(cert);

        loaded++;
    } while (true);

    BIO_free(biobuf);

    if (loaded == 0) {
        if (filetype == SSL_FILETYPE_PEM) {
            ErrorFormat(kSSLError[0], "no start line: cadata does not contain a certificate");

            return nullptr;
        }

        ErrorFormat(kSSLError[0], "not enough data: cadata does not contain a certificate");

        return nullptr;
    }

    err = ERR_peek_last_error();

    if ((filetype == SSL_FILETYPE_ASN1 &&
         ERR_GET_LIB(err) == ERR_LIB_ASN1 &&
         ERR_GET_REASON(err) == ASN1_R_HEADER_TOO_LONG) ||
        (filetype == SSL_FILETYPE_PEM &&
         ERR_GET_LIB(err) == ERR_LIB_PEM &&
         ERR_GET_REASON(err) == PEM_R_NO_START_LINE)) {
        ERR_clear_error();
    } else if (err != 0) {
        SSLError();

        return nullptr;
    }

    return ARGON_NIL_VALUE;
}

ARGON_METHOD(sslcontext_load_cafile, load_cafile,
             "",
             "s: cafile", false, false) {
    auto *self = (SSLContext *) _self;

    // TODO: UniqueLock lock(ctx->lock);

    errno = 0;
    if (SSL_CTX_load_verify_locations(self->ctx, (const char *) ARGON_RAW_STRING((String *) *args), nullptr) != 1) {
        if (errno != 0)
            ErrorFromErrno(errno);
        else
            SSLError();

        return nullptr;
    }

    return ARGON_NIL_VALUE;
}

ARGON_METHOD(sslcontext_load_capath, load_capath,
             "",
             "s: capath", false, false) {
    auto *self = (SSLContext *) _self;

    // TODO: UniqueLock lock(ctx->lock);

    errno = 0;
    if (SSL_CTX_load_verify_locations(self->ctx, nullptr, (const char *) ARGON_RAW_STRING((String *) *args)) != 1) {
        if (errno != 0)
            ErrorFromErrno(errno);
        else
            SSLError();

        return nullptr;
    }

    return ARGON_NIL_VALUE;
}

ARGON_METHOD(sslcontext_load_path_default, load_path_default,
             "",
             nullptr, false, false) {
    auto *self = (SSLContext *) _self;

    // TODO: UniqueLock lock(ctx->lock);

    if (!SSL_CTX_set_default_verify_paths(self->ctx)) {
        SSLError();

        ERR_clear_error();

        return nullptr;
    }

    return ARGON_NIL_VALUE;
}

ARGON_METHOD(sslcontext_get_stats, get_stats,
             "",
             nullptr, false, false) {
#define ADD_STAT(SSLNAME, KEY)                                          \
    if((tmp = IntNew(SSL_CTX_sess_##SSLNAME(self->ctx))) == nullptr)    \
        goto ERROR;                                                     \
    if(!DictInsert(dict, (KEY), (ArObject*)tmp)) {                      \
        Release(tmp);                                                   \
        goto ERROR;                                                     \
    } Release(tmp)

    auto *self = (SSLContext *) _self;
    Integer *tmp;
    Dict *dict;

    if ((dict = DictNew()) == nullptr)
        return nullptr;

    // TODO: UniqueLock lock(ctx->lock);

    ADD_STAT(number, "number");
    ADD_STAT(connect, "connect");
    ADD_STAT(connect_good, "connect_good");
    ADD_STAT(connect_renegotiate, "connect_renegotiate");
    ADD_STAT(accept, "accept");
    ADD_STAT(accept_good, "accept_good");
    ADD_STAT(accept_renegotiate, "accept_renegotiate");
    ADD_STAT(accept, "accept");
    ADD_STAT(hits, "hits");
    ADD_STAT(misses, "misses");
    ADD_STAT(timeouts, "timeouts");
    ADD_STAT(cache_full, "cache_full");

    return (ArObject *) dict;

    ERROR:
    Release(tmp);
    Release(dict);
    return nullptr;
}

ARGON_METHOD(sslcontext_set_check_hostname, set_check_hostname,
             "",
             "b: check", false, false) {
    auto *self = (SSLContext *) _self;

    bool check = ArBoolToBool((Boolean *) *args);

    // TODO: UniqueLock lock(ctx->lock);

    if (check && SSL_CTX_get_verify_mode(self->ctx) == SSL_VERIFY_NONE)
        SetVerifyMode(self, SSLVerify::CERT_REQUIRED);

    self->check_hname = check;

    return ARGON_NIL_VALUE;
}

ARGON_METHOD(sslcontext_set_ciphers, set_ciphers,
             "",
             "s: cipher", false, false) {
    auto *self = (SSLContext *) _self;

    // TODO: UniqueLock lock(ctx->lock);

    if (SSL_CTX_set_cipher_list(self->ctx, (const char *) ARGON_RAW_STRING((String *) *args)) == 0) {
        SSLError();

        ERR_clear_error();

        return nullptr;
    }

    return ARGON_NIL_VALUE;
}

ARGON_METHOD(sslcontext_set_max_version, set_max_version,
             "",
             "i: version", false, false) {
    auto *self = (SSLContext *) _self;

    // TODO: UniqueLock lock(ctx->lock);

    if (!MinMaxProtoVersion(self, (unsigned int) ((Integer *) *args)->sint, true))
        return nullptr;

    return ARGON_NIL_VALUE;
}

ARGON_METHOD(sslcontext_set_min_version, set_min_version,
             "",
             "i: version", false, false) {
    auto *self = (SSLContext *) _self;

    // TODO: UniqueLock lock(ctx->lock);

    if (!MinMaxProtoVersion(self, (unsigned int) ((Integer *) *args)->sint, false))
        return nullptr;

    return ARGON_NIL_VALUE;
}

ARGON_METHOD(sslcontext_set_num_tickets, set_num_tickets,
             "",
             "i: ticket", false, false) {
    auto *self = (SSLContext *) _self;

    unsigned long ticket = ((Integer *) *args)->sint;

    // TODO: UniqueLock lock(ctx->lock);

    if (self->protocol != SSLProtocol::TLS_SERVER) {
        ErrorFormat(kSSLError[0], "not a server context");

        return nullptr;
    }

    if (SSL_CTX_set_num_tickets(self->ctx, ticket) != 1) {
        ErrorFormat(kSSLError[0], "failed to set num tickets");

        return nullptr;
    }

    return ARGON_NIL_VALUE;
}

const FunctionDef sslcontext_methods[] = {
        sslcontext_sslcontext,

        sslcontext_load_cadata,
        sslcontext_load_cafile,
        sslcontext_load_capath,
        sslcontext_load_path_default,
        sslcontext_get_stats,
        sslcontext_set_check_hostname,
        sslcontext_set_ciphers,
        sslcontext_set_max_version,
        sslcontext_set_min_version,
        sslcontext_set_num_tickets,
        ARGON_METHOD_SENTINEL
};

const ObjectSlots sslcontext_objslot = {
        sslcontext_methods,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        -1
};

bool sslcontext_dtor(SSLContext *self) {
    SSL_CTX_free(self->ctx);
    Release(self->sni_callback);

    return true;
}

TypeInfo SSLContextType = {
        AROBJ_HEAD_INIT_TYPE,
        "SSLContext",
        nullptr,
        nullptr,
        sizeof(SSLContext),
        TypeInfoFlags::BASE,
        nullptr,
        (Bool_UnaryOp) sslcontext_dtor,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        &sslcontext_objslot,
        nullptr,
        nullptr,
        nullptr,
        nullptr
};
const TypeInfo *arlib::ssl::type_sslcontext_ = &SSLContextType;

SSLContext *arlib::ssl::SSLContextNew(SSLProtocol protocol) {
    const SSL_METHOD *method;
    X509_VERIFY_PARAM *params;
    SSLContext *ctx;
    long options;

    switch (protocol) {
        case SSLProtocol::TLS:
            method = TLS_method();
            break;
        case SSLProtocol::TLS_CLIENT:
            method = TLS_client_method();
            break;
        case SSLProtocol::TLS_SERVER:
            method = TLS_server_method();
            break;
        default:
            ErrorFormat(kSSLError[0], "invalid protocol %i", protocol);
            return nullptr;
    }

    if ((ctx = MakeObject<SSLContext>(&SSLContextType)) == nullptr)
        return nullptr;

    if ((ctx->ctx = SSL_CTX_new(method)) == nullptr) {
        Release(ctx);
        SSLError();
        return nullptr;
    }

    ctx->sni_callback = nullptr;
    ctx->protocol = protocol;

    ctx->verify_mode = SSLVerify::CERT_NONE;
    ctx->hostflags = X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS;

    if (protocol == SSLProtocol::TLS_CLIENT) {
        ctx->check_hname = true;
        SetVerifyMode(ctx, SSLVerify::CERT_REQUIRED);
    } else {
        ctx->check_hname = false;
        SetVerifyMode(ctx, SSLVerify::CERT_NONE);
    }

    options = SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;

#ifdef SSL_OP_NO_COMPRESSION
    options |= SSL_OP_NO_COMPRESSION;
#endif
#ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
    options |= SSL_OP_CIPHER_SERVER_PREFERENCE;
#endif
#ifdef SSL_OP_SINGLE_DH_USE
    options |= SSL_OP_SINGLE_DH_USE;
#endif
#ifdef SSL_OP_SINGLE_ECDH_USE
    options |= SSL_OP_SINGLE_ECDH_USE;
#endif
#ifdef SSL_OP_IGNORE_UNEXPECTED_EOF
    options |= SSL_OP_IGNORE_UNEXPECTED_EOF;
#endif

    SSL_CTX_set_options(ctx->ctx, options);

#ifdef SSL_MODE_RELEASE_BUFFERS
    /*
     * When we no longer need a read buffer or a write buffer for a given SSL,
     * then release the memory we were using to hold it.
     * Using this flag can save around 34k per idle SSL connection.
     * This flag has no effect on SSL v2 connections, or on DTLS connections.
     */
    SSL_CTX_set_mode(ctx->ctx, SSL_MODE_RELEASE_BUFFERS);
#endif

    /*
     * When X509_V_FLAG_TRUSTED_FIRST is set, which is always the case since OpenSSL 1.1.0,
     * construction of the certificate chain in X509_verify_cert(3) searches the trust store
     * for issuer certificates before searching the provided untrusted certificates.
     */
    params = SSL_CTX_get0_param(ctx->ctx);
    X509_VERIFY_PARAM_set_flags(params, X509_V_FLAG_TRUSTED_FIRST);
    X509_VERIFY_PARAM_set_hostflags(params, ctx->hostflags);

    ctx->post_handshake = false;
    SSL_CTX_set_post_handshake_auth(ctx->ctx, ctx->post_handshake);

    return ctx;
}