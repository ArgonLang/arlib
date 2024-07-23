// This source file is part of the Argon project.
//
// Licensed under the Apache License v2.0

#include <argon/vm/runtime.h>
#include <argon/vm/importer/import.h>

#include <version.h>

#include <argon/vm/datatype/bytes.h>

#include <compressor/compressor.h>
#include <compressor/lzma.h>

using namespace argon::vm::datatype;
using namespace arlib::compressor;
using namespace arlib::compressor::lzma;

Bytes *CompressOrFlush(LZMACompressor *lzc, unsigned char *buffer, ArSize length) {
    unsigned char *out_buf;
    ArSize out_buf_sz;
    ArSize index;

    auto action = LZMA_RUN;
    if (buffer == nullptr)
        action = LZMA_FINISH;

    out_buf_sz = kOUTPUT_BUFFER_SIZE;
    out_buf = (unsigned char *) argon::vm::memory::Alloc(out_buf_sz);
    if (out_buf == nullptr)
        return nullptr;

    auto *lstream = &lzc->lz_stream;

    index = 0;
    lstream->next_in = (unsigned char *) buffer;
    lstream->avail_in = length;

    do {
        lstream->next_out = (unsigned char *) (out_buf + index);
        lstream->avail_out = out_buf_sz - index;

        auto bz_result = lzma_code(lstream, action);
        if (bz_result != LZMA_OK && bz_result != LZMA_STREAM_END) {
            argon::vm::memory::Free(out_buf);

            ErrorFormat(kCompressorError[0], "LZMA compression failed");
            return nullptr;
        }

        if (bz_result == LZMA_STREAM_END)
            lzc->finished = true;

        auto compressed_size = out_buf_sz - lstream->avail_out;
        index += compressed_size;

        if (bz_result != LZMA_STREAM_END && lstream->avail_in > 0) {
            out_buf_sz += kOUTPUT_BUFFER_INCREMENT;

            auto *tmp = (unsigned char *) argon::vm::memory::Realloc(out_buf, out_buf_sz);
            if (tmp == nullptr) {
                argon::vm::memory::Free(out_buf);
                return nullptr;
            }

            out_buf = tmp;
        }
    } while (lstream->avail_in > 0);

    auto *ret = BytesNewHoldBuffer(out_buf, out_buf_sz, index, false);
    if (ret == nullptr) {
        argon::vm::memory::Free(out_buf);

        return nullptr;
    }

    return ret;
}

ARGON_FUNCTION(lzmacompressor_lzmacompressor, LZMACompressor,
               "Create a new LZMA compressor object.\n"
               "\n"
               "The preset parameter controls the compression-speed vs compression-ratio tradeoff. The higher the preset, "
               "the higher the compression ratio but slower the compression speed.\n"
               "\n"
               "The default preset is 6, which provides a good balance between compression and speed.\n"
               "\n"
               "- KWParameters:\n"
               "  - preset: Compression preset (0-9, optional, default is 6).\n"
               "- Returns: New LZMA compressor.\n",
               nullptr, false, true) {
    IntegerUnderlying preset;

    if (!KParamLookupInt((Dict *) kwargs, "preset", &preset, 6))
        return nullptr;

    auto *lcompress = MakeObject<LZMACompressor>(type_lzma_compressor_);
    if (lcompress != nullptr) {
        lcompress->lz_stream = LZMA_STREAM_INIT;
        lcompress->finished = false;

        new(&lcompress->lock) argon::vm::sync::RecursiveSharedMutex();

        auto ret = lzma_easy_encoder(&lcompress->lz_stream, preset, LZMA_CHECK_CRC64);
        if (ret != LZMA_OK) {
            Release(lcompress);

            ErrorFormat(kCompressorError[0], "failed to initialize LZMA encoder");

            return nullptr;
        }
    }

    return (ArObject *) lcompress;
}

// Inherited from Compressor trait
ARGON_METHOD_INHERITED(lzmacompressor_compress, compress) {
    ArBuffer buffer{};

    auto *self = (LZMACompressor *) _self;

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
ARGON_METHOD_INHERITED(lzmacompressor_flush, flush) {
    auto *self = (LZMACompressor *) _self;

    std::unique_lock _(self->lock);

    if (self->finished)
        return (ArObject *) BytesNew(0, true, false, false);

    return (ArObject *) CompressOrFlush(self, nullptr, 0);
}

const FunctionDef lzmacompressor_methods[] = {
        lzmacompressor_lzmacompressor,

        lzmacompressor_compress,
        lzmacompressor_flush,
        ARGON_METHOD_SENTINEL
};

const ObjectSlots lzmacompressor_objslot = {
        lzmacompressor_methods,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        -1
};

bool lzmacompressor_dtor(LZMACompressor *self) {
    self->lock.~RecursiveSharedMutex();

    lzma_end(&self->lz_stream);

    return true;
}

TypeInfo LZMACompressorType = {
        AROBJ_HEAD_INIT_TYPE,
        "LZMACompressor",
        nullptr,
        "Data compression using the LZMA compression algorithm.",
        sizeof(LZMACompressor),
        TypeInfoFlags::BASE,
        nullptr,
        (Bool_UnaryOp) lzmacompressor_dtor,
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
        &lzmacompressor_objslot,
        nullptr,
        nullptr,
        nullptr,
        nullptr
};
const TypeInfo *arlib::compressor::lzma::type_lzma_compressor_ = &LZMACompressorType;

ARGON_FUNCTION(lzmadecompressor_lzmadecompressor, LZMADecompressor,
               "Create a new LZMA decompressor object.\n"
               "\n"
               "- Returns: New LZMA decompressor object.\n",
               nullptr, false, false) {
    auto *lcompress = MakeObject<LZMACompressor>(type_lzma_decompressor_);
    if (lcompress != nullptr) {
        lcompress->lz_stream = LZMA_STREAM_INIT;
        lcompress->finished = false;

        new(&lcompress->lock)argon::vm::sync::RecursiveSharedMutex();

        auto ret = lzma_stream_decoder(&lcompress->lz_stream, UINT64_MAX, LZMA_CONCATENATED);
        if (ret != LZMA_OK) {
            Release(lcompress);

            ErrorFormat(kCompressorError[0], "failed to initialize LZMA decoder");

            return nullptr;
        }
    }

    return (ArObject *) lcompress;
}

// Inherited from Decompressor trait
ARGON_METHOD_INHERITED(lzmadecompressor_decompress, decompress) {
    ArBuffer buffer{};

    auto *self = (LZMACompressor *) _self;
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

    auto *lstream = &self->lz_stream;
    lzma_ret ret;

    lstream->next_in = buffer.buffer;
    lstream->avail_in = buffer.length;

    do {
        lstream->next_out = out_buf + index;
        lstream->avail_out = out_buffer_sz - index;

        ret = lzma_code(lstream, LZMA_RUN);
        if (ret != LZMA_OK && ret != LZMA_STREAM_END) {
            BufferRelease(&buffer);
            argon::vm::memory::Free(out_buf);

            ErrorFormat(kCompressorError[0], "LZMA decompression failed");
            return nullptr;
        }

        auto decompressed_size = (out_buffer_sz - index) - lstream->avail_out;
        index += decompressed_size;

        if (ret != LZMA_STREAM_END && lstream->avail_out == 0) {
            out_buffer_sz += kOUTPUT_BUFFER_INCREMENT;

            auto tmp = (unsigned char *) argon::vm::memory::Realloc(out_buf, out_buffer_sz);
            if (tmp == nullptr) {
                BufferRelease(&buffer);

                argon::vm::memory::Free(out_buf);

                return nullptr;
            }

            out_buf = tmp;
        }
    } while (ret != LZMA_STREAM_END && lstream->avail_in > 0);

    BufferRelease(&buffer);

    if (ret == LZMA_STREAM_END)
        self->finished = true;

    auto *bret = BytesNewHoldBuffer(out_buf, out_buffer_sz, index, false);
    if (bret == nullptr) {
        argon::vm::memory::Free(out_buf);

        return nullptr;
    }

    return (ArObject *) bret;
}

const FunctionDef lzmadecompressor_methods[] = {
        lzmadecompressor_lzmadecompressor,

        lzmadecompressor_decompress,
        ARGON_METHOD_SENTINEL
};

const ObjectSlots lzmadecompressor_objslot = {
        lzmadecompressor_methods,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        -1
};

TypeInfo LZMADecompressorType = {
        AROBJ_HEAD_INIT_TYPE,
        "LZMADecompressor",
        nullptr,
        "Decompressor for data that was compressed using the LZMA compression algorithm.",
        sizeof(LZMACompressor),
        TypeInfoFlags::BASE,
        nullptr,
        (Bool_UnaryOp) lzmacompressor_dtor,
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
        &lzmadecompressor_objslot,
        nullptr,
        nullptr,
        nullptr,
        nullptr
};
const TypeInfo *arlib::compressor::lzma::type_lzma_decompressor_ = &LZMADecompressorType;

const ModuleEntry lzma_entries[] = {
        MODULE_EXPORT_TYPE(type_lzma_compressor_),
        MODULE_EXPORT_TYPE(type_lzma_decompressor_),

        ARGON_MODULE_SENTINEL
};

bool LzmaInit(Module *self) {
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

    auto ok = TypeInit((TypeInfo *) type_lzma_compressor_, nullptr, bases, 1);

    Release(bases[0]);

    if (ok)
        ok = TypeInit((TypeInfo *) type_lzma_decompressor_, nullptr, bases + 1, 1);

    Release(bases[1]);

    return ok;
}

constexpr ModuleInit ModuleLzma = {
        "lzma",
        "This module provides support for compressing and decompressing data using the LZMA algorithm. "
        "LZMA offers a high compression ratio and is particularly effective for compressing large data.",
        ARLIB_VERSION,
        lzma_entries,
        LzmaInit,
        nullptr
};

ARGON_MODULE_INIT(ModuleLzma)
