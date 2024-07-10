// This source file is part of the Argon project.
//
// Licensed under the Apache License v2.0

#ifndef ARLIB_COMPRESSOR_ZLIB_H_
#define ARLIB_COMPRESSOR_ZLIB_H_

#include <zlib.h>

#include <argon/vm/sync/rsm.h>

#include <argon/vm/datatype/arobject.h>

namespace arlib::compressor::zlib {
    constexpr const int kOUTPUT_BUFFER_SIZE = 4096;
    constexpr const int kOUTPUT_BUFFER_INCREMENT = 2046;

    struct ZIPCompressor {
        AROBJ_HEAD;

        argon::vm::sync::RecursiveSharedMutex lock;

        z_stream zstream;

        bool finished;
    };
    extern const argon::vm::datatype::TypeInfo *type_zip_compressor_;
    extern const argon::vm::datatype::TypeInfo *type_zip_decompressor_;
} // namespace arlib::compressor::zlib

#endif // !ARLIB_COMPRESSOR_ZLIB_H_
