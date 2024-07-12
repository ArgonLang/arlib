// This source file is part of the Argon project.
//
// Licensed under the Apache License v2.0

#include <argon/vm/runtime.h>
#include <argon/vm/io/io.h>
#include <argon/vm/loop2/evloop.h>

#include <argon/vm/datatype/boolean.h>
#include <argon/vm/datatype/nil.h>

#include <ssl/ssl.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#undef ERROR

using namespace argon::vm::datatype;
using namespace argon::vm::loop2;
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

CallbackStatus ExecSSLWantOp(SSLSocket *socket, UserCB cb, int retvat) {
    switch (SSL_get_error(socket->ssl, retvat)) {
        case SSL_ERROR_WANT_READ:
            socket->want_status = SSL_ERROR_WANT_READ;

            if ((retvat = BIO_read(socket->out_bio, socket->buffer.buffer, (int) socket->buffer.capacity)) < 0)
                retvat = 0;

            if (!socket::SendRecvCB(socket->socket,
                                    (ArObject *) socket,
                                    cb,
                                    socket->buffer.buffer,
                                    retvat,
                                    socket->buffer.capacity))
                break;

            return CallbackStatus::CONTINUE;
        case SSL_ERROR_WANT_WRITE:
            if ((retvat = BIO_read(socket->out_bio, socket->buffer.buffer, (int) socket->buffer.capacity)) < 0)
                retvat = 0;

            if (!socket::SendCB(socket->socket,
                                (ArObject *) socket,
                                cb,
                                socket->buffer.buffer,
                                retvat,
                                0))
                break;

            return CallbackStatus::CONTINUE;
        default:
            SSLError();
            break;
    }

    return CallbackStatus::FAILURE;
}

CallbackStatus HandshakeCallback(const Event *event, SSLSocket *socket, int status) {
    int res;

    if (status < 0)
        socket->lock.Release();

    if (event != nullptr && socket->want_status == SSL_ERROR_WANT_READ) {
        if (BIO_write(socket->in_bio, event->buffer.data, (int) event->buffer.length) < 0) {
            socket->lock.Release();

            ErrorFormat(kSSLError[0], "handshake BIO_write error");

            return CallbackStatus::FAILURE;
        }
    }

    socket->want_status = 0;

    ERR_clear_error();

    if ((res = SSL_do_handshake(socket->ssl)) == 1) {
        assert(event != nullptr);

        socket->lock.Release();

        argon::vm::FiberSetAsyncResult(event->fiber, (ArObject *) Nil);

        return CallbackStatus::SUCCESS;
    }

    auto r_status = ExecSSLWantOp(socket, (UserCB) HandshakeCallback, res);
    if (r_status == CallbackStatus::FAILURE)
        socket->lock.Release();

    return r_status;
}

CallbackStatus ReadCallback(const Event *event, SSLSocket *socket, int status) {
    ArObject *ret;

    CallbackStatus r_status;

    size_t b_read;

    int res = 0;

    if (status < 0)
        goto CLEANUP;

    if (event != nullptr) {
        if (socket->want_status == SSL_ERROR_WANT_READ) {
            res = BIO_write(socket->in_bio, event->buffer.data, (int) event->buffer.length);
            if (res < 0) {
                ErrorFormat(kSSLError[0], "read BIO_write error");

                goto CLEANUP;
            }
        }

        socket->want_status = 0;

        ERR_clear_error();

        res = SSL_read_ex(socket->ssl, socket->user_buffer.buffer, socket->user_buffer.length, &b_read);
        if (res == 1) {
            if (socket->user_buffer.arBuffer.object == nullptr)
                ret = (ArObject *) BytesNewHoldBuffer(socket->user_buffer.buffer, socket->user_buffer.length,
                                                      b_read, true);
            else
                ret = (ArObject *) IntNew((IntegerUnderlying) b_read);

            if (ret == nullptr)
                goto CLEANUP;

            if (socket->user_buffer.arBuffer.object != nullptr)
                BufferRelease(&socket->user_buffer.arBuffer);

            socket->lock.Release();

            argon::vm::FiberSetAsyncResult(event->fiber, ret);

            Release(ret);

            return CallbackStatus::SUCCESS;
        }
    }

    if ((r_status = ExecSSLWantOp(socket, (UserCB) ReadCallback, res)) != CallbackStatus::FAILURE)
        return r_status;

    CLEANUP:
    if (socket->user_buffer.arBuffer.buffer != nullptr)
        BufferRelease(&socket->user_buffer.arBuffer);
    else
        argon::vm::memory::Free(socket->user_buffer.buffer);

    socket->lock.Release();

    return CallbackStatus::FAILURE;
}

CallbackStatus ShutdownCallback(const Event *event, SSLSocket *socket, int status) {
    int res;

    if (status < 0) {
        socket->lock.Release();

        return CallbackStatus::FAILURE;
    }

    if (event != nullptr && socket->want_status == SSL_ERROR_WANT_READ) {
        res = BIO_write(socket->in_bio, event->buffer.data, (int) event->buffer.length);
        if (res < 0) {
            socket->lock.Release();

            ErrorFormat(kSSLError[0], "shutdown BIO_write error");

            return CallbackStatus::FAILURE;
        }
    }

    socket->want_status = 0;

    ERR_clear_error();

    res = SSL_shutdown(socket->ssl);
    if (res == 1) {
        if (event != nullptr) {
            socket->lock.Release();

            auto *ret = (ArObject *) IncRef(Nil);

            argon::vm::FiberSetAsyncResult(event->fiber, ret);

            Release(ret);
        }

        return CallbackStatus::SUCCESS;
    }

    auto r_status = ExecSSLWantOp(socket, (UserCB) ShutdownCallback, res);
    if (r_status == CallbackStatus::FAILURE)
        socket->lock.Release();

    return r_status;
}

CallbackStatus UnwrapCallback(const Event *event, SSLSocket *socket, int status) {
    int res;

    if (status < 0) {
        socket->lock.Release();

        return CallbackStatus::FAILURE;
    }

    if (event != nullptr && socket->want_status == SSL_ERROR_WANT_READ) {
        res = BIO_write(socket->in_bio, event->buffer.data, (int) event->buffer.length);
        if (res < 0) {
            socket->lock.Release();

            ErrorFormat(kSSLError[0], "unwrap BIO_write error");

            return CallbackStatus::FAILURE;
        }
    }

    socket->want_status = 0;

    ERR_clear_error();

    res = SSL_shutdown(socket->ssl);
    if (res == 1) {
        if (event != nullptr) {
            argon::vm::FiberSetAsyncResult(event->fiber, (ArObject *) socket->socket);

            socket->lock.Release();
        }

        return CallbackStatus::SUCCESS;
    }

    auto r_status = ExecSSLWantOp(socket, (UserCB) UnwrapCallback, res);
    if (r_status == CallbackStatus::FAILURE)
        socket->lock.Release();

    return r_status;
}

CallbackStatus WriteCallback(const Event *event, SSLSocket *socket, int status) {
    ArObject *ret;

    size_t written;

    if (status < 0) {
        BufferRelease(&socket->user_buffer.arBuffer);

        socket->lock.Release();

        return CallbackStatus::FAILURE;
    }

    if (event != nullptr) {
        if (socket->want_status == 0) {
            socket->lock.Release();

            ret = (ArObject *) IntNew((IntegerUnderlying) event->buffer.length);

            argon::vm::FiberSetAsyncResult(event->fiber, ret);

            Release(ret);

            return CallbackStatus::SUCCESS;
        } else if (socket->want_status == SSL_ERROR_WANT_READ) {
            socket->want_status = 0;

            if (BIO_write(socket->in_bio, event->buffer.data, (int) event->buffer.length) < 0) {
                BufferRelease(&socket->user_buffer.arBuffer);

                socket->lock.Release();

                ErrorFormat(kSSLError[0], "write BIO_write error");

                return CallbackStatus::FAILURE;
            }
        }
    }

    socket->want_status = 0;

    ERR_clear_error();

    auto res = SSL_write_ex(socket->ssl, socket->user_buffer.buffer, socket->user_buffer.length, &written);
    if (res == 1) {
        auto b_written = BIO_read(socket->out_bio, socket->buffer.buffer, (int) socket->buffer.capacity);

        BufferRelease(&socket->user_buffer.arBuffer);

        socket->want_status = 0;

        if (!socket::SendCB(socket->socket, (ArObject *) socket, (UserCB) WriteCallback, socket->buffer.buffer,
                            b_written, 0)) {
            socket->lock.Release();

            return CallbackStatus::FAILURE;
        }

        return CallbackStatus::CONTINUE;
    }

    auto r_status = ExecSSLWantOp(socket, (UserCB) WriteCallback, res);
    if (r_status != CallbackStatus::FAILURE)
        return r_status;

    BufferRelease(&socket->user_buffer.arBuffer);

    socket->lock.Release();

    return CallbackStatus::FAILURE;
}

ARGON_METHOD(sslsocket_handshake, handshake,
             "Perform the SSL setup handshake.\n",
             nullptr, false, false) {
    auto *socket = (SSLSocket *) _self;

    if (!socket->lock.Lock())
        return nullptr;

    if (SSL_is_init_finished(socket->ssl)) {
        socket->lock.Release();

        return ARGON_NIL_VALUE;
    }

    HandshakeCallback(nullptr, socket, 0);

    return nullptr;
}

ARGON_METHOD(sslsocket_peercert, peercert,
             "Returns peer certificate.\n"
             "\n"
             "If there is no certificate for the peer on the other end of the connection, return an empty object. "
             "If the SSL handshake hasn't been done yet, this function start panicking state.\n"
             "\n"
             "- Parameter binary_form: Specifies whether to return the certificate as a dictionary or in binary form (DER).\n"
             "- Returns: Bytes object or Dict.\n",
             "b: binary_form", false, false) {
    auto *self = (SSLSocket *) _self;
    ArObject *ret;
    X509 *pc;

    if (!self->lock.Lock())
        return nullptr;

    if (!SSL_is_init_finished(self->ssl)) {
        self->lock.Release();

        ErrorFormat(kSSLError[0], "handshake not done yet");

        return nullptr;
    }

    pc = SSL_get_peer_certificate(self->ssl);

    self->lock.Release();

    if (ArBoolToBool((Boolean *) *args))
        ret = pc == nullptr ? (ArObject *) BytesNew(0, true, false, true)
                            : (ArObject *) CertToDer(pc);
    else
        ret = pc == nullptr ? (ArObject *) DictNew() : (ArObject *) DecodeCert(pc);

    X509_free(pc);

    return ret;
}

// Inherited from Reader trait
ARGON_METHOD_INHERITED(sslsocket_read, read) {
    auto *self = (SSLSocket *) _self;
    IntegerUnderlying bufsize = ((Integer *) args[0])->sint;

    size_t b_read;

    if (bufsize < 0) {
        ErrorFormat(kValueError[0], "size cannot be less than zero");

        return nullptr;
    }

    if (bufsize == 0)
        return (ArObject *) BytesNew(0, true, false, true);

    if (!self->lock.Lock())
        return nullptr;

    self->user_buffer.arBuffer.buffer = nullptr;

    if ((self->user_buffer.buffer = (unsigned char *) argon::vm::memory::Alloc(bufsize)) == nullptr)
        goto ERROR;

    self->user_buffer.length = bufsize;

    ERR_clear_error();

    if (SSL_read_ex(self->ssl, self->user_buffer.buffer, self->user_buffer.length, &b_read) > 0) {
        auto *ret = BytesNewHoldBuffer(self->user_buffer.buffer, self->user_buffer.length, b_read, true);
        if (ret == nullptr)
            goto ERROR;

        self->lock.Release();

        return (ArObject *) ret;
    }

    ReadCallback(nullptr, self, 0);

    return nullptr;

    ERROR:
    argon::vm::memory::Free(self->user_buffer.buffer);

    self->lock.Release();

    return nullptr;
}

// Inherited from Reader trait
ARGON_METHOD_INHERITED(sslsocket_readinto, readinto) {
    auto *self = (SSLSocket *) _self;
    auto offset = ((Integer *) args[1])->sint;

    size_t b_read;

    if (offset < 0)
        offset = 0;

    if (!self->lock.Lock())
        return nullptr;

    if (!BufferGet(*args, &self->user_buffer.arBuffer, BufferFlags::WRITE)) {
        self->lock.Release();

        return nullptr;
    }

    self->user_buffer.buffer = self->user_buffer.arBuffer.buffer + offset;
    self->user_buffer.length = self->user_buffer.arBuffer.length - offset;

    ERR_clear_error();

    if (SSL_read_ex(self->ssl, self->user_buffer.buffer, self->user_buffer.length, &b_read) > 0) {
        BufferRelease(&self->user_buffer.arBuffer);

        self->lock.Release();

        return (ArObject *) IntNew((IntegerUnderlying) b_read);
    }

    ReadCallback(nullptr, self, 0);

    return nullptr;
}

ARGON_METHOD(sslsocket_shutdown, shutdown,
             "This function close an SSL/TLS connection between a client and a server.\n",
             nullptr, false, false) {
    auto *self = (SSLSocket *) _self;

    if (!self->lock.Lock())
        return nullptr;

    SSL_shutdown(self->ssl);

    if (ShutdownCallback(nullptr, self, 0) == CallbackStatus::SUCCESS) {
        self->lock.Release();

        return (ArObject *) IncRef(Nil);
    }

    return nullptr;
}

ARGON_METHOD(sslsocket_unwrap, unwrap,
             "Performs the SSL shutdown handshake, and returns the underlying socket object.\n"
             "\n"
             "This can be used to go from encrypted operation over a connection to unencrypted. "
             "The returned socket should always be used for further communication instead of the original socket.\n"
             "\n"
             "- Returns: Argon socket.\n",
             nullptr, false, false) {

    auto *self = (SSLSocket *) _self;

    if (!self->lock.Lock())
        return nullptr;

    SSL_shutdown(self->ssl);

    if (UnwrapCallback(nullptr, self, 0) == CallbackStatus::SUCCESS) {
        self->lock.Release();

        return (ArObject *) IncRef(self->socket);
    }

    return nullptr;
}

ARGON_METHOD(sslsocket_verify_client, verify_client,
             "Requests post-handshake authentication (PHA) from a TLS 1.3 client.\n"
             "\n"
             "PHA can only be initiated for a TLS 1.3 connection from a server-side socket, "
             "after the initial TLS handshake and with PHA enabled on both sides.\n"
             "The method does not perform a cert exchange immediately. The server-side sends a CertificateRequest during "
             "the next write event and expects the client to respond with a certificate on the next read event.\n"
             "\n",
             nullptr, false, false) {
    auto *self = ((SSLSocket *) _self);

    if (!self->lock.Lock())
        return nullptr;

    if (SSL_verify_client_post_handshake(self->ssl) == 0) {
        SSLError();

        self->lock.Release();

        return nullptr;
    }

    self->lock.Release();

    return ARGON_NIL_VALUE;
}

// Inherited from Writer trait
ARGON_METHOD_INHERITED(sslsocket_write, write) {
    auto *self = (SSLSocket *) _self;

    if (self->lock.Lock()) {
        if (BufferGet(*args, &self->user_buffer.arBuffer, BufferFlags::READ)) {
            self->user_buffer.buffer = self->user_buffer.arBuffer.buffer;
            self->user_buffer.length = self->user_buffer.arBuffer.length;

            WriteCallback(nullptr, self, 0);
        } else
            self->lock.Release();
    }

    return nullptr;
}

const FunctionDef sslsocket_methods[] = {
        sslsocket_handshake,
        sslsocket_read,
        sslsocket_readinto,
        sslsocket_shutdown,
        sslsocket_verify_client,
        sslsocket_unwrap,
        sslsocket_write,

        ARGON_METHOD_SENTINEL
};

ArObject *alpn_selected_get(SSLSocket *self) {
    const unsigned char *out;
    unsigned int outlen;

    if (!self->lock.Lock())
        return nullptr;

    SSL_get0_alpn_selected(self->ssl, &out, &outlen);

    self->lock.Release();

    if (out == nullptr)
        return ARGON_NIL_VALUE;

    return (ArObject *) StringNew((const char *) out, outlen);
}

Tuple *CipherToTuple(const SSL_CIPHER *cipher) {
    const char *name;
    const char *proto;
    int bits;

    name = SSL_CIPHER_get_name(cipher);
    proto = SSL_CIPHER_get_version(cipher);
    bits = SSL_CIPHER_get_bits(cipher, nullptr);

    return TupleNew("ssi", name, proto, bits);
}

ArObject *cipher_get(SSLSocket *self) {
    const SSL_CIPHER *current;

    if (!self->lock.Lock())
        return nullptr;

    current = SSL_get_current_cipher(self->ssl);

    self->lock.Release();

    if (current == nullptr)
        return ARGON_NIL_VALUE;

    return (ArObject *) CipherToTuple(current);
}

ArObject *compression_get(SSLSocket *self) {
    const COMP_METHOD *comp_method;
    const char *name;

    if (!self->lock.Lock())
        return nullptr;

    comp_method = SSL_get_current_compression(self->ssl);

    self->lock.Release();

    if (comp_method == nullptr || COMP_get_type(comp_method) == NID_undef)
        return ARGON_NIL_VALUE;

    name = OBJ_nid2sn(COMP_get_type(comp_method));
    if (name == nullptr)
        return ARGON_NIL_VALUE;

    return (ArObject *) StringNew(name);
}

ArObject *pending_get(SSLSocket *self) {
    int length;

    if (!self->lock.Lock())
        return nullptr;

    length = SSL_pending(self->ssl);

    self->lock.Release();

    return (ArObject *) IntNew(length);
}

ArObject *session_reused_get(const SSLSocket *self) {
    return BoolToArBool(SSL_session_reused(self->ssl));
}

ArObject *shared_cipher_get(SSLSocket *self) {
    STACK_OF(SSL_CIPHER) *ciphers;
    Tuple *ret;
    int length;

    if (!self->lock.Lock())
        return nullptr;

    ciphers = SSL_get_ciphers(self->ssl);

    self->lock.Release();

    if (ciphers == nullptr)
        return ARGON_NIL_VALUE;

    length = sk_SSL_CIPHER_num(ciphers);

    if ((ret = TupleNew(length)) == nullptr)
        return nullptr;

    for (int i = 0; i < length; i++) {
        auto *tmp = (ArObject *) CipherToTuple(sk_SSL_CIPHER_value(ciphers, i));

        if (tmp == nullptr) {
            Release(ret);
            return nullptr;
        }

        TupleInsert(ret, tmp, i);

        Release(tmp);
    }

    return (ArObject *) ret;
}

ArObject *version_get(SSLSocket *self) {
    const char *version;

    if (!self->lock.Lock())
        return nullptr;

    if (!SSL_is_init_finished(self->ssl)) {
        self->lock.Release();

        return ARGON_NIL_VALUE;
    }

    version = SSL_get_version(self->ssl);

    self->lock.Release();

    return (ArObject *) StringNew(version);
}

const MemberDef sslsocket_members[] = {
        ARGON_MEMBER_GETSET("alpn_selected", (MemberGetFn) alpn_selected_get, nullptr),
        ARGON_MEMBER_GETSET("cipher", (MemberGetFn) cipher_get, nullptr),
        ARGON_MEMBER_GETSET("compression", (MemberGetFn) compression_get, nullptr),
        ARGON_MEMBER("hostname", MemberType::OBJECT, offsetof(SSLSocket, hostname), true),
        ARGON_MEMBER_GETSET("pending", (MemberGetFn) pending_get, nullptr),
        ARGON_MEMBER_GETSET("session_reused", (MemberGetFn) session_reused_get, nullptr),
        ARGON_MEMBER_GETSET("shared_cipher", (MemberGetFn) shared_cipher_get, nullptr),
        ARGON_MEMBER_GETSET("version", (MemberGetFn) version_get, nullptr),
        ARGON_MEMBER_SENTINEL
};

TypeInfo *sslsocket_bases[] = {
        (TypeInfo *) argon::vm::io::type_reader_t_,
        (TypeInfo *) argon::vm::io::type_writer_t_,
        nullptr
};

const ObjectSlots sslsocket_objslot = {
        sslsocket_methods,
        sslsocket_members,
        sslsocket_bases,
        nullptr,
        nullptr,
        -1
};

bool sslsocket_dtor(SSLSocket *self) {
    SSL_free(self->ssl);

    argon::vm::memory::Free(self->buffer.buffer);

    Release(self->context);
    Release(self->hostname);
    Release(self->socket);

    self->lock.~Mutex();

    return true;
}

TypeInfo SSLSocketType = {
        AROBJ_HEAD_INIT_TYPE,
        "SSLSocket",
        nullptr,
        "SSLSocket represents a secure socket connection using SSL/TLS protocols. It provides encrypted "
        "communication over an underlying network socket.",
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
        &sslsocket_objslot,
        nullptr,
        nullptr,
        nullptr,
        nullptr
};
const TypeInfo *arlib::ssl::type_sslsocket_ = &SSLSocketType;

SSLSocket *arlib::ssl::SSLSocketNew(SSLContext *context, socket::Socket *socket, String *hostname, bool server_side) {
    BIO *in_bio;
    BIO *out_bio;
    SSL *ssl;

    SSLSocket *sock;

    if (server_side && context->protocol == SSLProtocol::TLS_CLIENT) {
        ErrorFormat(kSSLError[0], "this context doesn't support server-side TLS");
        return nullptr;
    }

    if (!server_side && context->protocol == SSLProtocol::TLS_SERVER) {
        ErrorFormat(kSSLError[0], "this context doesn't support client-side TLS");
        return nullptr;
    }

    // Clear all SSL error
    ERR_clear_error();

    if ((in_bio = BIO_new(BIO_s_mem())) == nullptr) {
        ErrorFormat(kSSLError[0], "unable to allocate memory for read BIO");

        return nullptr;
    }

    if ((out_bio = BIO_new(BIO_s_mem())) == nullptr) {
        BIO_free(in_bio);

        ErrorFormat(kSSLError[0], "unable to allocate memory for write BIO");

        return nullptr;
    }

    if ((ssl = SSL_new(context->ctx)) == nullptr) {
        BIO_free(in_bio);
        BIO_free(out_bio);

        SSLError();

        return nullptr;
    }

    SSL_set_bio(ssl, in_bio, out_bio);

    SSL_set_mode(ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    SSL_clear_mode(ssl, SSL_MODE_AUTO_RETRY);

    SSL_set_read_ahead(ssl, 1);

    if ((sock = MakeObject<SSLSocket>(&SSLSocketType)) == nullptr) {
        SSL_free(ssl);

        return nullptr;
    }

    sock->in_bio = in_bio;
    sock->out_bio = out_bio;
    sock->ssl = ssl;

    sock->context = IncRef(context);
    sock->socket = IncRef(socket);
    sock->hostname = IncRef(hostname);

    SSL_set_app_data(sock->ssl, sock);

    if ((sock->buffer.buffer = (unsigned char *) argon::vm::memory::Alloc(kSSLWorkingBufferSize)) == nullptr) {
        Release(sock);

        return nullptr;
    }

    sock->buffer.length = 0;
    sock->buffer.capacity = kSSLWorkingBufferSize;

    new(&sock->lock) argon::vm::sync::Mutex();

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

    server_side ? SSL_set_accept_state(sock->ssl) : SSL_set_connect_state(sock->ssl);

    sock->protocol = server_side ? SSLProtocol::TLS_SERVER : SSLProtocol::TLS_CLIENT;

    return sock;
}