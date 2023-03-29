// This source file is part of the Argon project.
//
// Licensed under the Apache License v2.0

#include <argon/vm/datatype/module.h>

using namespace argon::vm::datatype;

bool RegexInit(Module *self){
    return true;
}

constexpr ModuleInit ModuleRegex = {
        "regex",
        "This module provides Perl-like regex support.",
        nullptr,
        RegexInit,
        nullptr
};

ARGON_MODULE_INIT(ModuleRegex)