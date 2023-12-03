// This source file is part of the Argon project.
//
// Licensed under the Apache License v2.0

#include <argon/vm/runtime.h>

#include <argon/vm/datatype/boolean.h>
#include <argon/vm/datatype/bytes.h>
#include <argon/vm/datatype/decimal.h>
#include <argon/vm/datatype/error.h>
#include <argon/vm/datatype/function.h>
#include <argon/vm/datatype/integer.h>
#include <argon/vm/datatype/module.h>
#include <argon/vm/datatype/nil.h>

#include <version.h>

#include <random/random.h>

#ifdef _ARGON_PLATFORM_WINDOWS
#include <windows.h>
#include <bcrypt.h>
#undef CONST
#else

#include <sys/random.h>

#endif

using namespace argon::vm::datatype;
using namespace arlib::random;

const FunctionDef random_t_methods[] = {
        ARGON_METHOD_STUB("discard",
                          "Advances the engine's state by a specified amount.\n"
                          "\n"
                          "- Parameter z: advances the internal by 'z' times.\n",
                          "iu: z", false, false),
        ARGON_METHOD_STUB("random",
                          "Return the next random floating point number in the range 0.0 <= X < 1.0.\n"
                          "\n"
                          "- Returns: Next random floating point number.\n",
                          nullptr, false, false),
        ARGON_METHOD_STUB("randbits",
                          "Returns a non-negative integer with k random bits.\n"
                          "\n"
                          "- Parameter k: Specifies the number of random bits.\n"
                          "- Returns: non-negative integer with k random bits.\n",
                          "iu: k", false, false),
        ARGON_METHOD_SENTINEL
};

const ObjectSlots random_t_objslot = {
        random_t_methods,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        -1
};

TypeInfo RandomTType = {
        AROBJ_HEAD_INIT_TYPE,
        "RandomT",
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
        &random_t_objslot,
        nullptr,
        nullptr,
        nullptr,
        nullptr
};
const TypeInfo *arlib::random::type_random_t_ = &RandomTType;

// DEFAULT GENERATOR

bool arlib::random::SystemRandom(unsigned char *buffer, ArSize buflen) {
#if defined(_ARGON_PLATFORM_DARWIN)
    if (getentropy(buffer, buflen) < 0) {
        ErrorFromErrno(errno);

        return false;
    }

    return true;
#elif defined(_ARGON_PLATFORM_LINUX)
    while(getrandom(buffer, buflen, 0) < buflen) {
        if(errno != EINTR) {
            ErrorFromErrno(errno);

            return false;
        }
    }

    return true;
#elif defined(_ARGON_PLATFORM_WINDOWS)
    BCRYPT_ALG_HANDLE hAlgorithm;
    NTSTATUS status;

    if(BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RNG_ALGORITHM, NULL, 0) != 0) {
        ErrorFromWinErr();
        return false;
    }

    status = BCryptGenRandom(hAlgorithm, (PUCHAR) buffer, buflen, 0);

    BCryptCloseAlgorithmProvider(hAlgorithm, 0);

    if(status != 0) {
        ErrorFromWinErr();
        return false;
    }

    return true;
#else
    ErrorFormat(kRuntimeError[0], "feature not supported for current operating system");
    return false;
#endif
}

MTEngine *arlib::random::MTEngineNew(argon::vm::datatype::ArSize seed) {
    auto mte = MakeObject<MTEngine>(type_mtengine_);

    if (mte != nullptr) {
        mte->engine = RaEngine(seed);
        mte->seed = seed;
    }

    return mte;
}

ARGON_FUNCTION(mtengine_mtengine, MTEngine,
               "Initialize the Mersenne Twister generator using a default seed or the one passed in.\n"
               "\n"
               "- KWParameters:\n"
               "  - seed: optional seed.\n"
               "- Returns: MTEngine object.\n",
               nullptr, false, true) {
    std::random_device rd;
    Integer *o_seed;

    ArSize seed = rd();

    if (kwargs != nullptr) {
        if(KParamLookup((Dict *) kwargs, (const char *) "seed",nullptr,(ArObject**)&o_seed,nullptr,true))
            return nullptr;

        if (o_seed != nullptr) {
            if (!AR_TYPEOF(o_seed, type_int_) && !AR_TYPEOF(o_seed, type_uint_)) {
                ErrorFormat(kTypeError[0], "%s expected '%s' got '%s'",
                            ARGON_RAW_STRING(((Function *) _func)->qname), type_int_->qname,
                            type_uint_->qname, AR_TYPE_QNAME(args[0]));

                Release(o_seed);

                return nullptr;
            }

            Release(o_seed);

            seed = o_seed->uint;
        }
    }

    return (ArObject *) MTEngineNew(seed);
}

ARGON_METHOD_INHERITED(mtengine_discard, discard) {
    auto self = (MTEngine *) _self;

    if (AR_TYPEOF(args[0], type_int_)) {
        auto *num = (const Integer *) args[0];

        if (num->sint < 0) {
            ErrorFormat(kValueError[0], "z must be greater than zero");

            return nullptr;
        }

        self->engine.discard(num->sint);
    } else
        self->engine.discard(((Integer *) args[0])->uint);

    return (ArObject *) IncRef(Nil);
}

ARGON_METHOD_INHERITED(mtengine_random, random) {
    std::uniform_real_distribution<DecimalUnderlying> dis(0.0, 1.0);

    return (ArObject *) DecimalNew(dis(((MTEngine *) _self)->engine));
}

ARGON_METHOD_INHERITED(mtengine_randbits, randbits) {
    auto self = (MTEngine *) _self;
    UIntegerUnderlying bits;

    if (AR_TYPEOF(args[0], type_int_)) {
        auto *num = (const Integer *) args[0];

        if (num->sint < 0) {
            ErrorFormat(kValueError[0], "k must be greater than zero");

            return nullptr;
        }

        bits = num->sint;
    } else
        bits = (((Integer *) args[0])->uint);

    if (bits >= _ARGON_ENVIRON) {
        ErrorFormat(kValueError[0], "%s param bits must be between [1,%d)",
                    ARGON_RAW_STRING(((Function *) _func)->qname), _ARGON_ENVIRON);
    }

    return (ArObject *) UIntNew(self->engine() >> (_ARGON_ENVIRON - bits));
}

const FunctionDef mtengine_methods[] = {
        mtengine_mtengine,

        mtengine_discard,
        mtengine_random,
        mtengine_randbits,
        ARGON_METHOD_SENTINEL
};

TypeInfo *mtengine_bases[] = {
        (TypeInfo *) type_random_t_,
        nullptr
};

const ObjectSlots mtengine_objslot = {
        mtengine_methods,
        nullptr,
        mtengine_bases,
        nullptr,
        nullptr,
        -1
};

ArObject *mtengine_repr(const MTEngine *self) {
    return (ArObject *) StringFormat("<%s (Mersenne Twister) with seed: %lu>", AR_TYPE_NAME(self), self->seed);
}

const TypeInfo MTEngineType = {
        AROBJ_HEAD_INIT_TYPE,
        "MTEngine",
        nullptr,
        nullptr,
        sizeof(MTEngine),
        TypeInfoFlags::BASE,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        (UnaryConstOp) mtengine_repr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        &mtengine_objslot,
        nullptr,
        nullptr,
        nullptr,
        nullptr
};
const TypeInfo *arlib::random::type_mtengine_ = &MTEngineType;

ARGON_FUNCTION(random_sysrand, sysrand,
               "Return a bytes string suitable for cryptographic use.\n"
               "\n"
               "This function returns random bytes from an OS-specific randomness source. "
               "The exact quality depends on the OS implementation.\n"
               "\n"
               "- Parameter size: Length of the bytes string to create.\n"
               "- Returns: Bytes string of random bytes.\n",
               "iu: size", false, false) {
    auto *num = (const Integer *) args[0];

    if (!AR_TYPEOF(args[0], type_int_) && num->sint < 0) {
        ErrorFormat(kValueError[0], "size must be greater than zero");

        return nullptr;
    }

    auto *buffer = (unsigned char *) argon::vm::memory::Alloc(num->uint);
    if (buffer == nullptr)
        return nullptr;

    if (!SystemRandom(buffer, num->uint)) {
        argon::vm::memory::Free(buffer);
        return nullptr;
    }

    auto *bytes = BytesNewHoldBuffer(buffer, num->uint, num->uint, true);
    if (bytes == nullptr)
        argon::vm::memory::Free(buffer);

    return (ArObject *) bytes;
}

const ModuleEntry random_entries[] = {
        MODULE_EXPORT_TYPE(type_mtengine_),
        MODULE_EXPORT_TYPE(type_random_t_),

        MODULE_EXPORT_FUNCTION(random_sysrand),
        ARGON_MODULE_SENTINEL
};

bool RandomInit(Module *self) {
    if (!TypeInit((TypeInfo *) type_random_t_, nullptr))
        return false;

    if (!TypeInit((TypeInfo *) type_mtengine_, nullptr))
        return false;

    auto *have_sysrand = (ArObject *) IncRef(False);

#if defined(_ARGON_PLATFORM_DARWIN) || defined(_ARGON_PLATFORM_LINUX) || defined(_ARGON_PLATFORM_WINDOWS)
    Replace(&have_sysrand, (ArObject *) IncRef(True));
#endif

    if (!ModuleAddObject(self, "HAVE_SYSRAND", have_sysrand, MODULE_ATTRIBUTE_DEFAULT)) {
        Release(have_sysrand);

        return false;
    }

    Release(have_sysrand);

    return true;
}

constexpr ModuleInit ModuleRandom = {
        "random",
        "This module implements pseudo-random number generators.",
        ARLIB_VERSION,
        random_entries,
        RandomInit,
        nullptr
};

ARGON_MODULE_INIT(ModuleRandom)
