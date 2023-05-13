// This source file is part of the Argon project.
//
// Licensed under the Apache License v2.0

#ifndef ARLIB_SSL_SSL_H_
#define ARLIB_SSL_SSL_H_

#include <argon/vm/datatype/arobject.h>
#include <argon/vm/datatype/tuple.h>

#include <argon/vm/io/socket/socket.h>

#include <argon/vm/sync/mutex.h>

#include <openssl/types.h>

namespace arlib::ssl {
    constexpr const char *kSSLError[] = {
            (const char *) "SSLError",
    };

    constexpr const unsigned int kSSLWorkingBufferSize = 4096; // Bytes

    enum class SSLProtocol : int {
        TLS,
        TLS_CLIENT,
        TLS_SERVER
    };

    enum class SSLVerify : int {
        CERT_NONE,
        CERT_OPTIONAL,
        CERT_REQUIRED
    };

    struct SSLContext {
        AROBJ_HEAD;

        std::mutex lock;

        argon::vm::datatype::ArObject *sni_callback;

        SSL_CTX *ctx;

        SSLProtocol protocol;
        SSLVerify verify_mode;

        unsigned int hostflags;
        bool check_hname;
        bool post_handshake;
    };
    extern const argon::vm::datatype::TypeInfo *type_sslcontext_;

    struct SSLSocket {
        AROBJ_HEAD;

        argon::vm::sync::Mutex lock;

        SSLContext *context;

        BIO *in_bio;
        BIO *out_bio;

        SSL *ssl;

        argon::vm::io::socket::Socket *socket;

        argon::vm::datatype::String *hostname;

        struct {
            unsigned char *buffer;

            size_t capacity;
            size_t length;
        } buffer;

        struct {
            argon::vm::datatype::ArBuffer arBuffer;

            unsigned char *buffer;
            size_t length;
        } user_buffer;

        SSLProtocol protocol;

        int want_status;
    };
    extern const argon::vm::datatype::TypeInfo *type_sslsocket_;

    argon::vm::datatype::Bytes *CertToDer(X509 *cert);

    argon::vm::datatype::Dict *DecodeCert(X509 *cert);

    argon::vm::datatype::Error *SSLErrorNew();

#ifdef _ARGON_PLATFORM_WINDOWS
    argon::vm::datatype::Tuple *EnumWindowsCert(const char *store_name);
#endif

    SSLContext *SSLContextNew(SSLProtocol protocol);

    SSLSocket *SSLSocketNew(SSLContext *context, argon::vm::io::socket::Socket *socket,
                            argon::vm::datatype::String *hostname, bool server_side);

    void SSLError();

} // namespace arlib::ssl

#endif // !ARLIB_SSL_SSL_H_
