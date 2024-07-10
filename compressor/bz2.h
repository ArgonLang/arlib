// This source file is part of the Argon project.
//
// Licensed under the Apache License v2.0

#ifndef ARLIB_COMPRESSOR_BZ2_H_
#define ARLIB_COMPRESSOR_BZ2_H_

#include <bzlib.h>

#include <argon/vm/sync/rsm.h>

#include <argon/vm/datatype/arobject.h>

namespace arlib::compressor::bz2 {
    constexpr const int kOUTPUT_BUFFER_SIZE = 4096;
    constexpr const int kOUTPUT_BUFFER_INCREMENT = 2046;

    struct BZ2Compressor {
        AROBJ_HEAD;

        argon::vm::sync::RecursiveSharedMutex lock;

        bz_stream bstream;

        bool finished;
    };
    extern const argon::vm::datatype::TypeInfo *type_bz2_compressor_;
    extern const argon::vm::datatype::TypeInfo *type_bz2_decompressor_;
} // namespace arlib::compressor::bz2

#endif // !ARLIB_COMPRESSOR_BZ2_H_
