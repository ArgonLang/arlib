// This source file is part of the Argon project.
//
// Licensed under the Apache License v2.0

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <argon/vm/runtime.h>

#include <argon/vm/datatype/module.h>

#include <version.h>

#include <ssl/ssl.h>

using namespace argon::vm::datatype;
using namespace argon::vm::io;
using namespace arlib::ssl;

bool ConfigureHostname(SSLSocket *socket, const char *name, ArSize length) {
    ASN1_OCTET_STRING *ip;

    if (length == 0 || *name == '.') {
        ErrorFormat(kValueError[0], "server_hostname cannot be an empty string or start with a leading dot");

        return false;
    }

    if ((ip = a2i_IPADDRESS(name)) == nullptr)
        ERR_clear_error();

    // SNI extension for non-IP hostname
    if (ip == nullptr && !SSL_set_tlsext_host_name(socket->ssl, name))
        goto ERROR;

    if (socket->context->check_hname) {
        X509_VERIFY_PARAM *param = SSL_get0_param(socket->ssl);

        if (ip == nullptr) {
            if (!X509_VERIFY_PARAM_set1_host(param, name, length))
                goto ERROR;
        } else {
            if (!X509_VERIFY_PARAM_set1_ip(param, ASN1_STRING_get0_data(ip), ASN1_STRING_length(ip)))
                goto ERROR;
        }
    }

    return true;

    ERROR:

    if (ip != nullptr)
        ASN1_OCTET_STRING_free(ip);

    SSLError();
    return false;
}

bool sslsocket_dtor(SSLSocket *self) {
    Release(self->context);
    Release(self->hostname);
    Release(self->socket);

    SSL_free(self->ssl);

    return true;
}

TypeInfo SSLSocketType = {
        AROBJ_HEAD_INIT_TYPE,
        "SSLSocket",
        nullptr,
        nullptr,
        sizeof(SSLSocket),
        TypeInfoFlags::BASE,
        nullptr,
        (Bool_UnaryOp) sslsocket_dtor,
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
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr
};
const TypeInfo *arlib::ssl::type_sslsocket_ = &SSLSocketType;

SSLSocket *arlib::ssl::SSLSocketNew(SSLContext *context, socket::Socket *socket, String *hostname, bool server_side) {
    SSLSocket *sock;

    if (server_side && context->protocol == SSLProtocol::TLS_CLIENT) {
        ErrorFormat(kSSLError[0], "this context doesn't support server-side TLS");
        return nullptr;
    }

    if (!server_side && context->protocol == SSLProtocol::TLS_SERVER) {
        ErrorFormat(kSSLError[0], "this context doesn't support client-side TLS");
        return nullptr;
    }

    if ((sock = MakeObject<SSLSocket>(&SSLSocketType)) == nullptr)
        return nullptr;

    sock->context = IncRef(context);
    sock->socket = IncRef(socket);
    sock->hostname = IncRef(hostname);

    // Clear all SSL error
    ERR_clear_error();

    if ((sock->ssl = SSL_new(context->ctx)) == nullptr) {
        Release(sock);

        SSLError();

        return nullptr;
    }

    SSL_set_app_data(sock->ssl, sock);
    SSL_set_fd(sock->ssl, socket->sock);

    SSL_set_mode(sock->ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_AUTO_RETRY);

    if (context->post_handshake && server_side) {
        int (*verify_cb)(int, X509_STORE_CTX *);

        int mode = SSL_get_verify_mode(sock->ssl);

        if (mode & SSL_VERIFY_PEER) {
            verify_cb = SSL_get_verify_callback(sock->ssl);

            mode |= SSL_VERIFY_POST_HANDSHAKE;

            SSL_set_verify(sock->ssl, mode, verify_cb);
        } else
            SSL_set_post_handshake_auth(sock->ssl, 1);
    }

    if (!IsNull((ArObject *) hostname) && !ConfigureHostname(sock,
                                                             (const char *) ARGON_RAW_STRING(hostname),
                                                             ARGON_RAW_STRING_LENGTH(hostname))) {
        Release(sock);

        return nullptr;
    }

    // TODO: asycn server_side ? SSL_set_accept_state(sock->ssl) : SSL_set_connect_state(sock->ssl);

    sock->protocol = server_side ? SSLProtocol::TLS_SERVER : SSLProtocol::TLS_CLIENT;

    return sock;
}