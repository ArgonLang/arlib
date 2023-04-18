// This source file is part of the Argon project.
//
// Licensed under the Apache License v2.0

#ifndef ARLIB_SSL_SSL_H_
#define ARLIB_SSL_SSL_H_

#include <argon/vm/datatype/arobject.h>
#include <argon/vm/datatype/tuple.h>

namespace arlib::ssl {
    constexpr const char *kSSLError[] = {
            (const char *) "SSLError",
    };

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

        argon::vm::datatype::ArObject *sni_callback;

        SSL_CTX *ctx;

        SSLProtocol protocol;
        SSLVerify verify_mode;

        unsigned int hostflags;
        bool check_hname;
        bool post_handshake;
    };
    extern const argon::vm::datatype::TypeInfo *type_sslcontext_;

    SSLContext *SSLContextNew(SSLProtocol protocol);

    argon::vm::datatype::Error *SSLErrorNew();

    void SSLError();

} // namespace arlib::ssl

#endif // !ARLIB_SSL_SSL_H_
