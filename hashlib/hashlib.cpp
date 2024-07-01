// This source file is part of the Argon project.
//
// Licensed under the Apache License v2.0

#include <argon/vm/runtime.h>

#include <argon/vm/datatype/bytes.h>
#include <argon/vm/datatype/nil.h>
#include <hashlib/hashlib.h>

using namespace argon::vm::datatype;
using namespace arlib::hashlib;

Tuple *alg_avail = nullptr;

const FunctionDef hash_t_methods[] = {
        ARGON_METHOD_STUB("digest",
                          "Return the digest of the data passed to the update method.\n"
                          "\n"
                          "KWParameters:\n"
                          "   - length: Sets the bit length of the output (for algorithms that expect it).\n"
                          "- Returns: A bytes object of the digest.\n",
                          nullptr, false, true),
        ARGON_METHOD_STUB("hexdigest",
                          "Return the digest of the data passed to the update method as a string of hexadecimal digits.\n"
                          "\n"
                          "KWParameters:\n"
                          "   - length: Sets the bit length of the output (for algorithms that expect it).\n"
                          "- Returns: A string of hexadecimal digits.\n",
                          nullptr, false, true),
        ARGON_METHOD_STUB("update",
                          "Update the hash object with the bytes-like object.\n"
                          "\n"
                          "- Parameter data: The data to hash.\n",
                          ": data", false, false),
        ARGON_METHOD_SENTINEL
};

const ObjectSlots hash_t_objslot = {
        hash_t_methods,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        -1
};

TypeInfo HashTType = {
        AROBJ_HEAD_INIT_TYPE,
        "HashT",
        nullptr,
        nullptr,
        0,
        TypeInfoFlags::TRAIT,
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
        &hash_t_objslot,
        nullptr,
        nullptr,
        nullptr,
        nullptr
};
const TypeInfo *arlib::hashlib::type_hash_t_ = &HashTType;

bool digest(HashContext *hctx, unsigned char *out_buf, unsigned int *out_len, int xof_length) {
    bool is_xof = EVP_MD_flags(EVP_MD_CTX_get0_md(hctx->ctx)) & EVP_MD_FLAG_XOF;

    EVP_MD_CTX *tmp_ctx = EVP_MD_CTX_new();
    if (tmp_ctx == nullptr) {
        ErrorFormat(kHashLibError[0], kHashLibError[1]);
        return false;
    }

    if (EVP_MD_CTX_copy_ex(tmp_ctx, hctx->ctx) != 1) {
        EVP_MD_CTX_free(tmp_ctx);

        ErrorFormat(kHashLibError[0], kHashLibError[2]);

        return false;
    }

    if (is_xof) {
        if (xof_length <= 0 || xof_length > EVP_MAX_MD_SIZE) {
            ErrorFormat(kHashLibError[0], kHashLibError[3], ARGON_RAW_STRING(hctx->alg_name));
            return false;
        }

        *out_len = xof_length;

        if (EVP_DigestFinalXOF(tmp_ctx, out_buf, xof_length) != 1) {
            EVP_MD_CTX_free(tmp_ctx);

            ErrorFormat(kHashLibError[0], kHashLibError[4]);

            return false;
        }
    } else {
        if (EVP_DigestFinal_ex(tmp_ctx, out_buf, out_len) != 1) {
            EVP_MD_CTX_free(tmp_ctx);

            ErrorFormat(kHashLibError[0], kHashLibError[5]);

            return false;
        }
    }

    EVP_MD_CTX_free(tmp_ctx);

    return true;
}

ARGON_FUNCTION(hashcontext_algorithms_available, algorithms_available,
               "Returns a tuple of the names of the hash algorithms available in hashlib library.\n"
               "\n"
               "- Returns: A tuple of strings representing available hash algorithms.\n",
               nullptr, false, false) {
    if (alg_avail)
        return (ArObject *) IncRef(alg_avail);

    List *alg_set = ListNew();
    if (alg_set == nullptr)
        return nullptr;

    OpenSSL_add_all_digests();

    OBJ_NAME_do_all(OBJ_NAME_TYPE_MD_METH, [](const OBJ_NAME *obj, void *arg) {
        auto *list = (List *) arg;

        if (argon::vm::IsPanickingFrame())
            return;

        auto *alg_name = StringNew(obj->name);
        if (alg_name != nullptr) {
            if (!ListAppend(list, (ArObject *) alg_name))
                return;

            Release(alg_name);
        }
    }, alg_set);

    if (argon::vm::IsPanickingFrame()) {
        Release(alg_set);

        return nullptr;
    }

    alg_avail = TupleConvertList(&alg_set);

    Release(alg_set);

    return (ArObject *) alg_avail;
}

// Inherited from HashT trait
ARGON_METHOD_INHERITED(hashcontext_digest, digest) {
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    IntegerUnderlying length;
    if (!KParamLookupInt((Dict *) kwargs, "length", &length, EVP_MAX_MD_SIZE))
        return nullptr;

    if (!digest((HashContext *) _self, md_value, &md_len, (int) length))
        return nullptr;

    return (ArObject *) BytesNew(md_value, md_len, true);
}

// Inherited from HashT trait
ARGON_METHOD_INHERITED(hashcontext_hexdigest, hexdigest) {
    unsigned char md_value[EVP_MAX_MD_SIZE];
    char hex_digest[EVP_MAX_MD_SIZE * 2 + 1];

    unsigned int md_len;

    IntegerUnderlying length;
    if (!KParamLookupInt((Dict *) kwargs, "length", &length, EVP_MAX_MD_SIZE))
        return nullptr;

    if (!digest((HashContext *) _self, md_value, &md_len, (int) length))
        return nullptr;

    for (unsigned int i = 0; i < md_len; i++)
        snprintf(hex_digest + (i * 2), 3, "%02x", md_value[i]);

    return (ArObject *) StringNew(hex_digest);
}

// Inherited from HashT trait
ARGON_METHOD_INHERITED(hashcontext_update, update) {
    auto *self = (HashContext *) _self;
    ArBuffer buffer{};

    if (!BufferGet(args[0], &buffer, BufferFlags::READ))
        return nullptr;

    if (EVP_DigestUpdate(self->ctx, buffer.buffer, buffer.length) != 1) {
        BufferRelease(&buffer);

        ErrorFormat(kHashLibError[0], kHashLibError[6]);

        return nullptr;
    }

    BufferRelease(&buffer);

    return IncRef(_self);
}

ARGON_FUNCTION(hashcontext_hashcontext, HashContext,
               "Create a new hash context.\n"
               "\n"
               "- Parameter name: The name of the hash algorithm.\n"
               "- Returns: A new HashContext object.\n",
               "s: name", false, false) {
    auto md = EVP_get_digestbyname((const char *) ARGON_RAW_STRING((String *) args[0]));
    if (md == nullptr) {
        ErrorFormat(kHashLibError[0], kHashLibError[7], args[0]);
        return nullptr;
    }

    auto ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        ErrorFormat(kHashLibError[0], kHashLibError[8]);

        return nullptr;
    }

    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        ErrorFormat(kHashLibError[0], kHashLibError[9]);

        return nullptr;
    }

    // Get SSL Algorithm name
    auto *ssl_name = EVP_MD_get0_name(md);
    auto *alg_name = StringNew(ssl_name);
    if (alg_name == nullptr) {
        EVP_MD_CTX_free(ctx);

        return nullptr;
    }

    auto *ret = MakeObject<HashContext>(type_hashcontext_);
    if (ret == nullptr) {
        EVP_MD_CTX_free(ctx);

        return nullptr;
    }

    ret->alg_name = alg_name;
    ret->ctx = ctx;

    return (ArObject *) ret;
}

const FunctionDef hashcontext_methods[] = {
        hashcontext_hashcontext,
        hashcontext_algorithms_available,

        hashcontext_digest,
        hashcontext_hexdigest,
        hashcontext_update,
        ARGON_METHOD_SENTINEL
};

ArObject *hashcontext_member_get_name(const HashContext *self) {
    return (ArObject *) IncRef(self->alg_name);
}

const MemberDef hashcontext_members[] = {
        ARGON_MEMBER_GETSET("name", (MemberGetFn) hashcontext_member_get_name, nullptr),
        ARGON_MEMBER_SENTINEL
};

TypeInfo *hashcontext_bases[] = {
        (TypeInfo *) type_hash_t_,
        nullptr
};

const ObjectSlots hashcontext_objslot = {
        hashcontext_methods,
        hashcontext_members,
        hashcontext_bases,
        nullptr,
        nullptr,
        -1
};

bool hashcontext_dtor(HashContext *self) {
    Release(self->alg_name);

    EVP_MD_CTX_free(self->ctx);

    return true;
}

TypeInfo HashContextType = {
        AROBJ_HEAD_INIT_TYPE,
        "HashContext",
        nullptr,
        "A hash object representing the state of a cryptographic hash computation. "
        "Supports various hash algorithms and provides methods for updating and finalizing the hash.",
        sizeof(HashContext),
        TypeInfoFlags::BASE,
        nullptr,
        (Bool_UnaryOp) hashcontext_dtor,
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
        &hashcontext_objslot,
        nullptr,
        nullptr,
        nullptr,
        nullptr
};
const TypeInfo *arlib::hashlib::type_hashcontext_ = &HashContextType;

const ModuleEntry hashlib_entries[] = {
        MODULE_EXPORT_TYPE(type_hash_t_),
        MODULE_EXPORT_TYPE(type_hashcontext_),

        ARGON_MODULE_SENTINEL
};

bool HashlibInit(Module *self) {
    if (!TypeInit((TypeInfo *) type_hash_t_, nullptr))
        return false;

    if (!TypeInit((TypeInfo *) type_hashcontext_, nullptr))
        return false;

    return true;
}

bool HashlibFini(Module *self) {
    Release(alg_avail);

    return true;
}

constexpr ModuleInit ModuleHashlib = {
        "hashlib",
        "This module implements a common interface to many different secure hash and message digest algorithms.",
        ARLIB_VERSION,
        hashlib_entries,
        HashlibInit,
        HashlibFini
};

ARGON_MODULE_INIT(ModuleHashlib)
