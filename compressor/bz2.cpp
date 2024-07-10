// This source file is part of the Argon project.
//
// Licensed under the Apache License v2.0

#include <argon/vm/runtime.h>
#include <argon/vm/importer/import.h>

#include <version.h>

#include <argon/vm/datatype/bytes.h>

#include <compressor/compressor.h>
#include <compressor/bz2.h>

using namespace argon::vm::datatype;
using namespace arlib::compressor;
using namespace arlib::compressor::bz2;

Bytes *CompressOrFlush(BZ2Compressor *bzc, unsigned char *buffer, ArSize length) {
    unsigned char *out_buf;
    ArSize out_buf_sz;
    ArSize index;

    int action = BZ_RUN;

    if (buffer != nullptr) {
        out_buf_sz = length + (length / 100) + 600;

        out_buf = (unsigned char *) argon::vm::memory::Alloc(out_buf_sz);
        if (out_buf == nullptr)
            return nullptr;
    } else {
        out_buf_sz = kOUTPUT_BUFFER_SIZE;

        out_buf = (unsigned char *) argon::vm::memory::Alloc(out_buf_sz);
        if (out_buf == nullptr)
            return nullptr;

        action = BZ_FINISH;
    }

    auto *bstream = &bzc->bstream;

    index = 0;
    bstream->next_in = (char *) buffer;
    bstream->avail_in = length;

    do {
        bstream->next_out = (char *) (out_buf + index);
        bstream->avail_out = out_buf_sz - index;

        auto bz_result = BZ2_bzCompress(bstream, action);
        if (bz_result != BZ_RUN_OK && bz_result != BZ_STREAM_END) {
            argon::vm::memory::Free(out_buf);

            ErrorFormat(kCompressorError[0], "BZip2 compression failed");
            return nullptr;
        }

        if (bz_result == BZ_STREAM_END)
            bzc->finished = true;

        auto compressed_size = out_buf_sz - bstream->avail_out;
        index += compressed_size;

        if (bz_result != BZ_STREAM_END && bstream->avail_in > 0) {
            out_buf_sz += kOUTPUT_BUFFER_INCREMENT;

            auto *tmp = (unsigned char *) argon::vm::memory::Realloc(out_buf, out_buf_sz);
            if (tmp == nullptr) {
                argon::vm::memory::Free(out_buf);
                return nullptr;
            }

            out_buf = tmp;
        }
    } while (bstream->avail_in > 0);

    auto *ret = BytesNewHoldBuffer(out_buf, out_buf_sz, index, false);
    if (ret == nullptr) {
        argon::vm::memory::Free(out_buf);

        return nullptr;
    }

    return ret;
}

ARGON_FUNCTION(bz2compressor_bz2compressor, BZ2Compressor,
               "Create a new BZ2 compressor object.\n"
               "\n"
               "- KWParameters:\n"
               "  - level: Compression level (1-9, optional, default is 9).\n"
               "- Returns: New BZ2 compressor.\n",
               nullptr, false, true) {
    IntegerUnderlying level;

    if (!KParamLookupInt((Dict *) kwargs, "level", &level, 9))
        return nullptr;

    if (level < 1 || level > 9) {
        ErrorFormat(kCompressorError[0], "BZ2 compression level must be between 1 and 9");
        return nullptr;
    }

    auto *bcompress = MakeObject<BZ2Compressor>(type_bz2_compressor_);
    if (bcompress != nullptr) {
        new(&bcompress->lock) argon::vm::sync::RecursiveSharedMutex();

        bcompress->finished = false;

        argon::vm::memory::MemoryZero(&bcompress->bstream, sizeof(bz_stream));

        int bz_result = BZ2_bzCompressInit(&bcompress->bstream, (int) level, 0, 0);
        if (bz_result != BZ_OK) {
            Release(bcompress);

            ErrorFormat(kCompressorError[0], "failed to initialize BZip2 compressor");
            return nullptr;
        }
    }

    return (ArObject *) bcompress;
}

// Inherited from Compressor trait
ARGON_METHOD_INHERITED(bz2compressor_compress, compress) {
    ArBuffer buffer{};

    auto *self = (BZ2Compressor *) _self;

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
ARGON_METHOD_INHERITED(bz2compressor_flush, flush) {
    auto *self = (BZ2Compressor *) _self;

    std::unique_lock _(self->lock);

    if (self->finished)
        return (ArObject *) BytesNew(0, true, false, false);

    return (ArObject *) CompressOrFlush(self, nullptr, 0);
}

const FunctionDef bz2compressor_methods[] = {
        bz2compressor_bz2compressor,

        bz2compressor_compress,
        bz2compressor_flush,
        ARGON_METHOD_SENTINEL
};

const ObjectSlots bz2compressor_objslot = {
        bz2compressor_methods,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        -1
};

bool bz2compressor_dtor(BZ2Compressor *self) {
    if (AR_GET_TYPE(self) == type_bz2_compressor_)
        BZ2_bzCompressEnd(&self->bstream);
    else
        BZ2_bzDecompressEnd(&self->bstream);

    self->lock.~RecursiveSharedMutex();

    return true;
}

TypeInfo BZ2CompressorType = {
        AROBJ_HEAD_INIT_TYPE,
        "BZ2Compressor",
        nullptr,
        nullptr,
        sizeof(BZ2Compressor),
        TypeInfoFlags::BASE,
        nullptr,
        (Bool_UnaryOp) bz2compressor_dtor,
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
        &bz2compressor_objslot,
        nullptr,
        nullptr,
        nullptr,
        nullptr
};
const TypeInfo *arlib::compressor::bz2::type_bz2_compressor_ = &BZ2CompressorType;

ARGON_FUNCTION(bz2decompressor_bz2decompressor, BZ2Decompressor,
               "Create a new BZ2 decompressor object.\n"
               "\n"
               "- Returns: New BZ2 decompressor object.\n",
               nullptr, false, false) {
    auto *bcompress = MakeObject<BZ2Compressor>(type_bz2_decompressor_);
    if (bcompress != nullptr) {
        new(&bcompress->lock) argon::vm::sync::RecursiveSharedMutex();

        bcompress->finished = false;

        argon::vm::memory::MemoryZero(&bcompress->bstream, sizeof(bz_stream));

        int bz_result = BZ2_bzDecompressInit(&bcompress->bstream, 0, 0);
        if (bz_result != BZ_OK) {
            Release(bcompress);

            ErrorFormat(kCompressorError[0], "failed to initialize BZip2 decompressor");
            return nullptr;
        }
    }

    return (ArObject *) bcompress;
}

// Inherited from Decompressor trait
ARGON_METHOD_INHERITED(bz2decompressor_decompress, decompress) {
    ArBuffer buffer{};

    auto *self = (BZ2Compressor *) _self;
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

    auto *bstream = &self->bstream;
    int ret;

    bstream->next_in = (char *) buffer.buffer;
    bstream->avail_in = buffer.length;

    do {
        bstream->next_out = (char *) out_buf + index;
        bstream->avail_out = out_buffer_sz - index;

        ret = BZ2_bzDecompress(bstream);
        if (ret != BZ_OK && ret != BZ_STREAM_END) {
            BufferRelease(&buffer);
            argon::vm::memory::Free(out_buf);

            ErrorFormat(kCompressorError[0], "BZip2 decompression failed");
            return nullptr;
        }

        auto decompressed_size = (out_buffer_sz - index) - bstream->avail_out;
        index += decompressed_size;

        if (ret != BZ_STREAM_END && bstream->avail_out == 0) {
            out_buffer_sz += kOUTPUT_BUFFER_INCREMENT;

            auto tmp = (unsigned char *) argon::vm::memory::Realloc(out_buf, out_buffer_sz);
            if (tmp == nullptr) {
                BufferRelease(&buffer);

                argon::vm::memory::Free(out_buf);

                return nullptr;
            }

            out_buf = tmp;
        }
    } while (ret != BZ_STREAM_END && bstream->avail_in > 0);

    BufferRelease(&buffer);

    if (ret == BZ_STREAM_END)
        self->finished = true;

    auto *bret = BytesNewHoldBuffer(out_buf, out_buffer_sz, index, false);
    if (bret == nullptr) {
        argon::vm::memory::Free(out_buf);

        return nullptr;
    }

    return (ArObject *) bret;
}

const FunctionDef bz2decompressor_methods[] = {
        bz2decompressor_bz2decompressor,

        bz2decompressor_decompress,
        ARGON_METHOD_SENTINEL
};

const ObjectSlots bz2decompressor_objslot = {
        bz2decompressor_methods,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        -1
};

TypeInfo BZ2DecompressorType = {
        AROBJ_HEAD_INIT_TYPE,
        "BZ2Decompressor",
        nullptr,
        nullptr,
        sizeof(BZ2Compressor),
        TypeInfoFlags::BASE,
        nullptr,
        (Bool_UnaryOp) bz2compressor_dtor,
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
        &bz2decompressor_objslot,
        nullptr,
        nullptr,
        nullptr,
        nullptr
};
const TypeInfo *arlib::compressor::bz2::type_bz2_decompressor_ = &BZ2DecompressorType;

const ModuleEntry bz2_entries[] = {
        MODULE_EXPORT_TYPE(type_bz2_compressor_),
        MODULE_EXPORT_TYPE(type_bz2_decompressor_),

        ARGON_MODULE_SENTINEL
};

bool BZ2Init(Module *self) {
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

    auto ok = TypeInit((TypeInfo *) type_bz2_compressor_, nullptr, bases, 1);

    Release(bases[0]);

    if (ok)
        ok = TypeInit((TypeInfo *) type_bz2_decompressor_, nullptr, bases + 1, 1);

    Release(bases[1]);

    return ok;
}

constexpr ModuleInit ModuleBZ2 = {
        "bz2",
        "This module provides support for compressing and decompressing data using the BZip2 algorithm. "
        "BZip2 offers a good balance between compression ratio and speed, and is effective for a wide range of data types.",
        ARLIB_VERSION,
        bz2_entries,
        BZ2Init,
        nullptr
};

ARGON_MODULE_INIT(ModuleBZ2)
