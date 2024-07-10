// This source file is part of the Argon project.
//
// Licensed under the Apache License v2.0

#include <argon/vm/runtime.h>

#include <version.h>

#include <compressor/compressor.h>

using namespace argon::vm::datatype;
using namespace arlib::compressor;

const FunctionDef compressor_methods[] = {
        ARGON_METHOD_STUB("compress",
                          "Compress data incrementally.\n"
                          "\n"
                          "Provide data to the compressor object.\n"
                          "When you have finished providing data to the compressor, call the flush() method to finish "
                          "the compression process.\n"
                          "\n"
                          "- Parameter data: Bufferable object containing the data to compress.\n"
                          "- Returns: A bytes object containing compressed data.\n",
                          ": data", false, false),
        ARGON_METHOD_STUB("flush",
                          "Finish the compression process.\n"
                          "\n"
                          "Returns a bytes object containing any remaining compressed data. You must not use the compressor "
                          "object after calling this method. This method may be called more than once. Subsequent calls will return empty bytes objects.\n"
                          "\n"
                          "- Returns: A bytes object containing any remaining compressed data.\n",
                          nullptr, false, false),
        ARGON_METHOD_SENTINEL
};

const ObjectSlots compressor_objslot = {
        compressor_methods,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        -1
};

TypeInfo CompressorType = {
        AROBJ_HEAD_INIT_TYPE,
        "Compressor",
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
        &compressor_objslot,
        nullptr,
        nullptr,
        nullptr,
        nullptr
};
const TypeInfo *arlib::compressor::type_compressor_t_ = &CompressorType;

const FunctionDef decompressor_methods[] = {
        ARGON_METHOD_STUB("decompress",
                          "Decompress data incrementally.\n"
                          "\n"
                          "This method decompresses the input data incrementally. It can be called "
                          "multiple times with new chunks of compressed data until the entire "
                          "compressed stream has been processed.\n"
                          "\n"
                          "The method returns a Bytes object containing the decompressed data "
                          "produced from the input. If the input does not produce any output "
                          "(which can happen due to the nature of some compression algorithms), "
                          "an empty Bytes object is returned.\n"
                          "\n"
                          "- Parameter data: Bufferable object containing the data to compress.\n"
                          "- Returns: A Bytes object containing the decompressed data.\n",
                          ": data", false, false),
        ARGON_METHOD_SENTINEL
};

const ObjectSlots decompressor_objslot = {
        decompressor_methods,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        -1
};

TypeInfo DecompressorType = {
        AROBJ_HEAD_INIT_TYPE,
        "Decompressor",
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
        &decompressor_objslot,
        nullptr,
        nullptr,
        nullptr,
        nullptr
};
const TypeInfo *arlib::compressor::type_decompressor_t_ = &DecompressorType;

const ModuleEntry compressor_entries[] = {
        MODULE_EXPORT_TYPE(type_compressor_t_),
        MODULE_EXPORT_TYPE(type_decompressor_t_),

        ARGON_MODULE_SENTINEL
};

bool CompressorInit(Module *self) {
    if(!TypeInit((TypeInfo*)type_compressor_t_, nullptr))
        return false;

    if(!TypeInit((TypeInfo*)type_decompressor_t_, nullptr))
        return false;

    return true;
}

constexpr ModuleInit ModuleCompressor = {
        "compressor",
        "",
        ARLIB_VERSION,
        compressor_entries,
        CompressorInit,
        nullptr
};

ARGON_MODULE_INIT(ModuleCompressor)
