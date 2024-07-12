// This source file is part of the Argon project.
//
// Licensed under the Apache License v2.0

#include <argon/vm/runtime.h>
#include <argon/vm/importer/import.h>

#include <version.h>

#include <argon/vm/datatype/bytes.h>

#include <compressor/compressor.h>
#include <compressor/zlib.h>

using namespace argon::vm::datatype;
using namespace arlib::compressor;
using namespace arlib::compressor::zlib;

Bytes *CompressOrFlush(ZIPCompressor *dc, unsigned char *buffer, ArSize length) {
    unsigned char *out_buf;
    ArSize out_buf_sz;
    ArSize index;

    int flush = Z_NO_FLUSH;

    if (buffer != nullptr) {
        out_buf_sz = deflateBound(&dc->zstream, length);

        out_buf = (unsigned char *) argon::vm::memory::Alloc(out_buf_sz);
        if (out_buf == nullptr)
            return nullptr;
    } else {
        out_buf_sz = kOUTPUT_BUFFER_SIZE;

        out_buf = (unsigned char *) argon::vm::memory::Alloc(out_buf_sz);
        if (out_buf == nullptr)
            return nullptr;

        flush = Z_FINISH;
    }

    auto *zstream = &dc->zstream;

    index = 0;
    zstream->next_in = buffer;
    zstream->avail_in = length;

    do {
        zstream->next_out = out_buf + index;
        zstream->avail_out = out_buf_sz - index;

        auto z_result = deflate(zstream, flush);
        if (z_result != Z_OK && z_result != Z_STREAM_END) {
            argon::vm::memory::Free(out_buf);

            ErrorFormat(kCompressorError[0], "DEFLATE compression failed");
            return nullptr;
        }

        if (z_result == Z_STREAM_END)
            dc->finished = true;

        auto compressed_size = out_buf_sz - zstream->avail_out;
        index += compressed_size;

        if (z_result != Z_STREAM_END && zstream->avail_in > 0) {
            out_buf_sz += kOUTPUT_BUFFER_INCREMENT;

            auto *tmp = (unsigned char *) argon::vm::memory::Realloc(out_buf, out_buf_sz);
            if (tmp == nullptr) {
                argon::vm::memory::Free(out_buf);
                return nullptr;
            }

            out_buf = tmp;
        }
    } while (zstream->avail_in > 0);

    auto *ret = BytesNewHoldBuffer(out_buf, out_buf_sz, index, false);
    if (ret == nullptr) {
        argon::vm::memory::Free(out_buf);

        return nullptr;
    }

    return ret;
}

ARGON_FUNCTION(zipcompressor_zipcompressor, ZIPCompressor,
               "Create a new DEFLATE compressor object.\n"
               "\n"
               "- KWParameters:\n"
               "  - level: Compression level (0-9, optional, default is 6).\n"
               "- Returns: New DEFLATE compressor.\n",
               nullptr, false, true) {
    IntegerUnderlying level;

    if (!KParamLookupInt((Dict *) kwargs, "level", &level, 6))
        return nullptr;

    if (level < 0 || level > 9) {
        ErrorFormat(kCompressorError[0], "DEFLATE compression level must be between 0 and 9");
        return nullptr;
    }

    auto *dcompress = MakeObject<ZIPCompressor>(type_zip_compressor_);
    if (dcompress != nullptr) {
        new(&dcompress->lock) argon::vm::sync::RecursiveSharedMutex();

        dcompress->finished = false;

        argon::vm::memory::MemoryZero(&dcompress->zstream, sizeof(z_stream));

        int z_result = deflateInit2(&dcompress->zstream, level, Z_DEFLATED, -MAX_WBITS, 8, Z_DEFAULT_STRATEGY);
        if (z_result != Z_OK) {
            Release(dcompress);

            ErrorFormat(kCompressorError[0], "failed to initialize DEFLATE compressor");
            return nullptr;
        }
    }

    return (ArObject *) dcompress;
}

// Inherited from Compressor trait
ARGON_METHOD_INHERITED(zipcompressor_compress, compress) {
    ArBuffer buffer{};

    auto *self = (ZIPCompressor *) _self;

    std::unique_lock _(self->lock);

    if (self->finished) {
        ErrorFormat(kCompressorError[0], "compression is already finished");
        return nullptr;
    }

    if (!BufferGet(args[0], &buffer, BufferFlags::READ))
        return nullptr;

    auto ret = CompressOrFlush(self, buffer.buffer, buffer.length);

    BufferRelease(&buffer);

    return (ArObject *) ret;
}

// Inherited from Compressor trait
ARGON_METHOD_INHERITED(zipcompressor_flush, flush) {
    auto *self = (ZIPCompressor *) _self;

    std::unique_lock _(self->lock);

    if (self->finished)
        return (ArObject *) BytesNew(0, true, false, false);

    return (ArObject *) CompressOrFlush(self, nullptr, 0);
}

const FunctionDef zipcompressor_methods[] = {
        zipcompressor_zipcompressor,

        zipcompressor_compress,
        zipcompressor_flush,
        ARGON_METHOD_SENTINEL
};

const ObjectSlots zipcompressor_objslot = {
        zipcompressor_methods,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        -1
};

bool zipcompressor_dtor(ZIPCompressor *self) {
    if (AR_GET_TYPE(self) == type_zip_compressor_)
        deflateEnd(&self->zstream);
    else
        inflateEnd(&self->zstream);

    self->lock.~RecursiveSharedMutex();

    return true;
}

TypeInfo ZIPCompressorType = {
        AROBJ_HEAD_INIT_TYPE,
        "ZIPCompressor",
        nullptr,
        "Data compression using the DEFLATE compression algorithm.",
        sizeof(ZIPCompressor),
        TypeInfoFlags::BASE,
        nullptr,
        (Bool_UnaryOp) zipcompressor_dtor,
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
        &zipcompressor_objslot,
        nullptr,
        nullptr,
        nullptr,
        nullptr
};
const TypeInfo *arlib::compressor::zlib::type_zip_compressor_ = &ZIPCompressorType;

ARGON_FUNCTION(zipdecompressor_zipdecompressor, ZIPDecompressor,
               "Create a new DEFLATE decompressor object.\n"
               "\n"
               "- Returns: New DEFLATE decompressor object.\n",
               nullptr, false, false) {
    auto *dcompress = MakeObject<ZIPCompressor>(type_zip_decompressor_);
    if (dcompress != nullptr) {
        new(&dcompress->lock) argon::vm::sync::RecursiveSharedMutex();

        dcompress->finished = false;

        argon::vm::memory::MemoryZero(&dcompress->zstream, sizeof(z_stream));

        int z_result = inflateInit2(&dcompress->zstream, -MAX_WBITS);
        if (z_result != Z_OK) {
            Release(dcompress);

            ErrorFormat(kCompressorError[0], "failed to initialize DEFLATE decompressor");
            return nullptr;
        }
    }

    return (ArObject *) dcompress;
}

// Inherited from Decompressor trait
ARGON_METHOD_INHERITED(zipdecompressor_decompress, decompress) {
    ArBuffer buffer{};

    auto *self = (ZIPCompressor *) _self;
    unsigned char *out_buf;

    unsigned int out_buffer_sz = kOUTPUT_BUFFER_SIZE;
    unsigned int index = 0;

    std::unique_lock _(self->lock);

    if (self->finished) {
        ErrorFormat(kCompressorError[0], "decompression is already finished");
        return nullptr;
    }

    if (!BufferGet(args[0], &buffer, BufferFlags::READ))
        return nullptr;

    if ((out_buf = (unsigned char *) argon::vm::memory::Alloc(out_buffer_sz)) == nullptr) {
        BufferRelease(&buffer);
        return nullptr;
    }

    auto *zstream = &self->zstream;
    int ret;

    zstream->next_in = buffer.buffer;
    zstream->avail_in = buffer.length;

    do {
        zstream->next_out = out_buf + index;
        zstream->avail_out = out_buffer_sz - index;

        ret = inflate(zstream, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END) {
            BufferRelease(&buffer);
            argon::vm::memory::Free(out_buf);

            ErrorFormat(kCompressorError[0], "DEFLATE decompression failed");
            return nullptr;
        }

        auto decompressed_size = (out_buffer_sz - index) - zstream->avail_out;
        index += decompressed_size;

        if (ret != Z_STREAM_END && zstream->avail_out == 0) {
            out_buffer_sz += kOUTPUT_BUFFER_INCREMENT;

            auto tmp = (unsigned char *) argon::vm::memory::Realloc(out_buf, out_buffer_sz);
            if (tmp == nullptr) {
                BufferRelease(&buffer);

                argon::vm::memory::Free(out_buf);

                return nullptr;
            }

            out_buf = tmp;
        }
    } while (ret != Z_STREAM_END && zstream->avail_in > 0);

    BufferRelease(&buffer);

    if (ret == Z_STREAM_END)
        self->finished = true;

    auto *bret = BytesNewHoldBuffer(out_buf, out_buffer_sz, index, false);
    if (bret == nullptr) {
        argon::vm::memory::Free(out_buf);

        return nullptr;
    }

    return (ArObject *) bret;
}

const FunctionDef zipdecompressor_methods[] = {
        zipdecompressor_zipdecompressor,

        zipdecompressor_decompress,
        ARGON_METHOD_SENTINEL
};

const ObjectSlots zipdecompressor_objslot = {
        zipdecompressor_methods,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        -1
};

TypeInfo ZIPDecompressorType = {
        AROBJ_HEAD_INIT_TYPE,
        "ZIPDecompressor",
        nullptr,
        "Decompressor for data that was compressed using the DEFLATE compression algorithm.",
        sizeof(ZIPCompressor),
        TypeInfoFlags::BASE,
        nullptr,
        (Bool_UnaryOp) zipcompressor_dtor,
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
        &zipdecompressor_objslot,
        nullptr,
        nullptr,
        nullptr,
        nullptr
};
const TypeInfo *arlib::compressor::zlib::type_zip_decompressor_ = &ZIPDecompressorType;

const ModuleEntry zlib_entries[] = {
        MODULE_EXPORT_TYPE(type_zip_compressor_),
        MODULE_EXPORT_TYPE(type_zip_decompressor_),

        ARGON_MODULE_SENTINEL
};

bool ZLIBInit(Module *self) {
    TypeInfo *bases[2] = {};

    auto *fiber = argon::vm::GetFiber();

    // Import compressor module
    auto *mod = argon::vm::importer::LoadModule(fiber->context->imp, "compressor", nullptr);
    if (mod == nullptr)
        return false;

    // Load Compressor trait
    bases[0] = (TypeInfo *) ModuleLookup(mod, "Compressor", nullptr);
    if (bases[0] == nullptr) {
        Release(mod);

        return false;
    }

    // Load Decompressor traits
    bases[1] = (TypeInfo *) ModuleLookup(mod, "Decompressor", nullptr);
    if (bases[1] == nullptr) {
        Release(bases[0]);
        Release(mod);

        return false;
    }

    Release(mod);

    auto ok = TypeInit((TypeInfo *) type_zip_compressor_, nullptr, bases, 1);

    Release(bases[0]);

    if (ok)
        ok = TypeInit((TypeInfo *) type_zip_decompressor_, nullptr, bases + 1, 1);

    Release(bases[1]);

    return ok;
}

constexpr ModuleInit ModuleZLIB = {
        "zlib",
        "This module provides support for compressing and decompressing data using the DEFLATE algorithm. "
        "DEFLATE is a widely used compression method that combines LZ77 algorithm and Huffman coding.",
        ARLIB_VERSION,
        zlib_entries,
        ZLIBInit,
        nullptr
};

ARGON_MODULE_INIT(ModuleZLIB)
