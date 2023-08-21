// This source file is part of the Argon project.
//
// Licensed under the Apache License v2.0

#ifndef ARLIB_RANDOM_RANDOM_H_
#define ARLIB_RANDOM_RANDOM_H_

#include <random>

#include <argon/util/macros.h>

#include <argon/vm/datatype/arobject.h>

#if _ARGON_ENVIRON == 32
using RaEngine = std::mt19937;
#else
using RaEngine = std::mt19937_64;
#endif

namespace arlib::random {
    struct MTEngine {
        AROBJ_HEAD;

        RaEngine engine;

        argon::vm::datatype::ArSize seed;
    };
    extern const argon::vm::datatype::TypeInfo *type_mtengine_;

    extern const argon::vm::datatype::TypeInfo *type_random_t_;

    bool SystemRandom(unsigned char *buffer, argon::vm::datatype::ArSize buflen);

    MTEngine *MTEngineNew(argon::vm::datatype::ArSize seed);

} // namespace arlib::random

#endif // !ARLIB_RANDOM_RANDOM_H_
