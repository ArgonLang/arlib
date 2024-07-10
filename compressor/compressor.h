// This source file is part of the Argon project.
//
// Licensed under the Apache License v2.0

#ifndef ARLIB_COMPRESSOR_COMPRESSOR_H_
#define ARLIB_COMPRESSOR_COMPRESSOR_H_

#include <argon/util/macros.h>

#include <argon/vm/datatype/arobject.h>

namespace arlib::compressor {
    constexpr const char *kCompressorError[] = {
            (const char *) "CompressorError"
    };

    extern const argon::vm::datatype::TypeInfo *type_compressor_t_;
    extern const argon::vm::datatype::TypeInfo *type_decompressor_t_;
} // namespace arlib::compressor

#endif // !ARLIB_COMPRESSOR_COMPRESSOR_H_
