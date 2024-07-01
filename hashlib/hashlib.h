// This source file is part of the Argon project.
//
// Licensed under the Apache License v2.0

#ifndef ARLIB_HASHLIB_HASHLIB_H_
#define ARLIB_HASHLIB_HASHLIB_H_

#include <openssl/evp.h>

#include <argon/util/macros.h>

#include <argon/vm/datatype/arobject.h>

namespace arlib::hashlib {
    constexpr const char *kHashLibError[] = {
            (const char *) "HashlibError",
            (const char *) "failed to create temporary digest context",
            (const char *) "failed to copy digest context",
            (const char *) "invalid output length for %",
            (const char *) "failed to finalize XOF digest",
            (const char *) "failed to finalize digest",
            (const char *) "failed to update digest",
            (const char *) "unknown hash algorithm: %s",
            (const char *) "failed to create digest context",
            (const char *) "failed to initialize digest"
    };

    struct HashContext {
        AROBJ_HEAD;

        argon::vm::datatype::String *alg_name;

        EVP_MD_CTX *ctx;
    };
    extern const argon::vm::datatype::TypeInfo *type_hashcontext_;

    extern const argon::vm::datatype::TypeInfo *type_hash_t_;
} // namespace arlib::hashlib

#endif // !ARLIB_HASHLIB_HASHLIB_H_
