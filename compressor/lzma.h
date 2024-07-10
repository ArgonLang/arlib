// This source file is part of the Argon project.
//
// Licensed under the Apache License v2.0

#ifndef ARLIB_COMPRESSOR_LZMA_H_
#define ARLIB_COMPRESSOR_LZMA_H_

#include <lzma.h>

#include <argon/vm/sync/rsm.h>

#include <argon/vm/datatype/arobject.h>

namespace arlib::compressor::lzma {
    constexpr const int kOUTPUT_BUFFER_SIZE = 4096;
    constexpr const int kOUTPUT_BUFFER_INCREMENT = 2046;

    struct LZMACompressor {
        AROBJ_HEAD;

        argon::vm::sync::RecursiveSharedMutex lock;

        lzma_stream lzma_stream;

        bool finished;
    };
    extern const argon::vm::datatype::TypeInfo *type_lzma_compressor_;
    extern const argon::vm::datatype::TypeInfo *type_lzma_decompressor_;
} // namespace arlib::compressor::lzma

#endif // !ARLIB_COMPRESSOR_LZMA_H_
