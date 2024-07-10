// This source file is part of the Argon project.
//
// Licensed under the Apache License v2.0

#ifndef ARLIB_COMPRESSOR_ZIPFILE_H_
#define ARLIB_COMPRESSOR_ZIPFILE_H_

#include <zip.h>

#include <argon/vm/sync/rsm.h>

#include <argon/vm/datatype/arobject.h>
#include <argon/vm/datatype/arstring.h>

namespace arlib::compressor::zipfile {
    constexpr const unsigned long long kBUFFER_MAX_SIZE = 1024 * 1024; // 1MB

    constexpr const char *kZipFileError[] = {
            (const char *) "ZipFileError",
            (const char *) "failed to close ZIP file: %s",
            (const char *) "failed to create directory entry: %s",
            (const char *) "failed to add directory to archive: %s",
            (const char *) "failed to set directory attributes: %s",
            (const char *) "failed to set directory modification time: %s",
            (const char *) "failed to get file stats: %s",
            (const char *) "failed to read file contents: %s",
            (const char *) "failed to open file in archive: %s",
            (const char *) "failed to read from zip file: %s",
            (const char *) "error reading file in zip: %s",
            (const char *) "failed to create zip source: %s",
            (const char *) "failed to add file to archive: %s",
            (const char *) "failed to set compression method: %s",
            (const char *) "failed to add data to archive: %s",
            (const char *) "archive is closed",
            (const char *) "there is no item named '%s' in the archive",
            (const char *) "failed to create directory: %s",
            (const char *) "failed to get file name: %s"
    };

    struct ZipFile {
        AROBJ_HEAD;

        argon::vm::sync::RecursiveSharedMutex lock;

        zip_t *archive;

        argon::vm::datatype::String *filename;
        argon::vm::datatype::String *mode;

        int compression_method;

        bool is_open;
    };
    extern const argon::vm::datatype::TypeInfo *type_zipfile_;

} // namespace arlib::compressor::zipfile

#endif // !ARLIB_COMPRESSOR_ZIPFILE_H_
