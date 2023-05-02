// This source file is part of the Argon project.
//
// Licensed under the Apache License v2.0

#include <openssl/err.h>

#include <argon/vm/runtime.h>

#include <argon/vm/datatype/module.h>

#include <version.h>

#include <ssl/ssl.h>

using namespace argon::vm::datatype;
using namespace arlib::ssl;

const ModuleEntry ssl_entries[] = {
        MODULE_EXPORT_TYPE(type_sslcontext_),
        MODULE_EXPORT_TYPE(type_sslsocket_),
        ARGON_MODULE_SENTINEL
};

bool SSLInit(Module *self) {
#define AddIntConstant(name, value)                 \
    if(!ModuleAddIntConstant(self, #name, value))   \
        return false

    if (!TypeInit((TypeInfo *) arlib::ssl::type_sslcontext_, nullptr))
        return false;

    if (!TypeInit((TypeInfo *) arlib::ssl::type_sslsocket_, nullptr))
        return false;

    return true;
#undef AddIntConstant
}

bool SSLFini([[maybe_unused]]Module *self) {
    return true;
}

constexpr ModuleInit ModuleSSL = {
        "ssl",
        "This module provides access to SSL/TLS encryption and peer authentication facilities "
        "for network sockets (client & server side).",
        ARLIB_VERSION,
        ssl_entries,
        SSLInit,
        SSLFini
};

ARGON_MODULE_INIT(ModuleSSL)

Error *arlib::ssl::SSLErrorNew() {
    char buf[256] = {};
    Error *err;

    if (ERR_error_string(ERR_get_error(), buf) == nullptr)
        err = ErrorNew(kSSLError[0], "unknown error");
    else
        err = ErrorNew(kSSLError[0], buf);

    return err;
}

void arlib::ssl::SSLError() {
    Error *err = SSLErrorNew();

    if (err != nullptr) {
        argon::vm::Panic((ArObject *) err);
        Release(err);
    }
}
