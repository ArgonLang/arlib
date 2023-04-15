// This source file is part of the Argon project.
//
// Licensed under the Apache License v2.0

#include <argon/vm/runtime.h>

#include <argon/vm/datatype/module.h>

#include <version.h>

using namespace argon::vm::datatype;

const ModuleEntry ssl_entries[] = {
        ARGON_MODULE_SENTINEL
};

bool SSLInit(Module *self) {
#define AddIntConstant(name, value)                 \
    if(!ModuleAddIntConstant(self, #name, value))   \
        return false

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
