// This source file is part of the Argon project.
//
// Licensed under the Apache License v2.0

#include <ctime>
#include <sys/stat.h>

#include <zip.h>
#include <zlib.h>

#include <argon/util/macros.h>

#ifdef _ARGON_PLATFORM_WINDOWS

#include <direct.h>

#endif

#include <argon/vm/runtime.h>

#include <version.h>

#include <argon/vm/datatype/arstring.h>
#include <argon/vm/datatype/bytes.h>
#include <argon/vm/datatype/error.h>
#include <argon/vm/datatype/list.h>
#include <argon/vm/datatype/nil.h>

#include <compressor/zipfile.h>

using namespace argon::vm::datatype;
using namespace arlib::compressor::zipfile;

bool CreateDirectories(char *path) {
    char *p = path;

    while (*p != '\0') {
        if (*p == '/') {
            char tmp = *p;
            *p = '\0';

#ifndef _ARGON_PLATFORM_WINDOWS
            if (mkdir(path, 0755) != 0) {
#else
            if (_mkdir(path) != 0) {
#endif
                if (errno != EEXIST) {
                    ErrorFormat(kOSError[0], "failed to create directory '%s': %s", path, strerror(errno));

                    *p = tmp;

                    return false;
                }
            }

            *p = tmp;
        }
        p++;
    }

    // Handle the case where the path ends with a directory
    if (strlen(path) > 0 && path[strlen(path) - 1] != '/') {
#ifndef _ARGON_PLATFORM_WINDOWS
        if (mkdir(path, 0755) != 0) {
#else
        if (_mkdir(path) != 0) {
#endif
            if (errno != EEXIST) {
                ErrorFormat(kOSError[0], "failed to create directory '%s': %s", path, strerror(errno));

                return false;
            }
        }
    }

    return true;
}

Error *ZipErrorNew(int ze) {
    zip_error_t error;

    zip_error_init_with_code(&error, ze);

    auto err = ErrorNew(kZipFileError[0], zip_error_strerror(&error));

    zip_error_fini(&error);

    return err;
}

String *NormalizePath(const String *filename, const String *path) {
    if (!IsTrue((ArObject *) path))
        return StringNew(ARGON_RAW_STRING(filename), ARGON_RAW_STRING_LENGTH(filename) + 1);

    auto *nix = StringIntern("/");
    auto win = StringIntern("\\");

    if (nix == nullptr || win == nullptr) {
        Release(nix);
        Release(win);

        return nullptr;
    }

    auto *fullpath = StringFormat("%s/%s", ARGON_RAW_STRING(path), ARGON_RAW_STRING(filename));
    if (fullpath == nullptr) {
        Release(nix);
        Release(win);

        return nullptr;
    }

    auto *normalized = StringReplace(fullpath, win, nix, -1);

    Release(nix);
    Release(win);
    Release(fullpath);

    return normalized;
}

String *ExtractFile(ZipFile *self, String *filename, const String *path) {
    struct zip_stat st{};

    auto index = zip_name_locate(self->archive, (const char *) ARGON_RAW_STRING(filename), 0);
    if (index == -1) {
        ErrorFormat(kZipFileError[0], kZipFileError[16], ARGON_RAW_STRING(filename));

        return nullptr;
    }

    // Get file info
    if (zip_stat_index(self->archive, index, 0, &st) != 0) {
        ErrorFormat(kZipFileError[0], kZipFileError[6], zip_strerror(self->archive));

        return nullptr;
    }

    // Open the file in the archive
    auto *zf = zip_fopen_index(self->archive, index, 0);
    if (zf == nullptr) {
        ErrorFormat(kZipFileError[0], kZipFileError[8], zip_strerror(self->archive));

        return nullptr;
    }

    auto buflen = st.size;
    if (buflen > kBUFFER_MAX_SIZE)
        buflen = kBUFFER_MAX_SIZE;

    auto *buffer = (char *) argon::vm::memory::Alloc(buflen);
    if (buffer == nullptr) {
        zip_fclose(zf);

        return nullptr;
    }

    String *fullpath;
    if (StringRFind(filename, "/") != -1 || IsTrue((ArObject *) path)) {
        fullpath = NormalizePath(filename, path);
        if (fullpath == nullptr) {
            argon::vm::memory::Free(buffer);

            zip_fclose(zf);

            return nullptr;
        }

        // WARNING: RAW String manipulation
        char *mkpath = (char *) ARGON_RAW_STRING(fullpath);

        auto *lsep = strrchr(mkpath, '/');
        if (lsep != nullptr) {
            *lsep = '\0';

            if (!CreateDirectories(mkpath)) {
                argon::vm::memory::Free(buffer);

                Release(fullpath);

                zip_fclose(zf);

                return nullptr;
            }

            *lsep = '/';
        }
    } else
        fullpath = IncRef(filename);

    // Open the output file
    auto *output_file = fopen((const char *) ARGON_RAW_STRING(fullpath), "wb");
    if (output_file == nullptr) {
        argon::vm::memory::Free(buffer);

        ErrorFormat(kOSError[0], "failed to create output file: %s", strerror(errno));

        Release(fullpath);

        zip_fclose(zf);

        return nullptr;
    }

    // Extract the file
    zip_int64_t bytes_read;
    while ((bytes_read = zip_fread(zf, buffer, buflen)) > 0) {
        if (fwrite(buffer, 1, bytes_read, output_file) != bytes_read) {
            argon::vm::memory::Free(buffer);

            ErrorFormat(kOSError[0], "failed to write to output file: %s", strerror(errno));

            Release(fullpath);

            fclose(output_file);

            zip_fclose(zf);

            return nullptr;
        }
    }

    if (bytes_read < 0) {
        argon::vm::memory::Free(buffer);

        ErrorFormat(kZipFileError[0], kZipFileError[9], zip_file_strerror(zf));

        Release(fullpath);

        fclose(output_file);

        zip_fclose(zf);

        return nullptr;
    }

    argon::vm::memory::Free(buffer);

    zip_fclose(zf);

    fclose(output_file);

    return fullpath;
}

void ZipError(int ze) {
    auto *err = ZipErrorNew(ze);

    if (err != nullptr) {
        argon::vm::Panic((ArObject *) err);
        Release(err);
    }
}

ARGON_FUNCTION(zipfile_zipfile, ZipFile,
               "Open a ZIP file.\n"
               "\n"
               "- Parameter file: Path to the ZIP file.\n"
               "- KWParameters:\n"
               "  - mode: The mode can be 'r' to read an existing file, 'w' to truncate "
               "and write a new file, 'a' to append to an existing file (default='r').\n"
               "  - method: Compression method to use when writing the archive (default=ZIP_CM_DEFLATE).\n"
               "- Returns: A new ZipFile object.\n",
               "s: file", false, true) {
    String *mode;
    auto *filename = (const char *) ARGON_RAW_STRING((String *) args[0]);

    IntegerUnderlying zip_method;

    int flags = ZIP_RDONLY;
    int error;

    bool default_mode;

    if (!KParamLookupStr((Dict *) kwargs, "mode", &mode, nullptr, &default_mode))
        return nullptr;

    if (!KParamLookupInt((Dict *) kwargs, "method", &zip_method, ZIP_CM_DEFLATE))
        return nullptr;

    if (!default_mode) {
        if (StringEqual(mode, "r"))
            flags = ZIP_RDONLY;
        else if (StringEqual(mode, "w"))
            flags = ZIP_CREATE | ZIP_TRUNCATE;
        else if (StringEqual(mode, "a"))
            flags = ZIP_CREATE;
        else {
            ErrorFormat(kValueError[0], "invalid mode. Use 'r', 'w', or 'a'");
            return nullptr;
        }
    }

    zip_t *archive = zip_open(filename, flags, &error);
    if (!archive) {
        ZipError(error);
        return nullptr;
    }

    auto *zfile = MakeObject<ZipFile>(type_zipfile_);
    if (zfile == nullptr) {
        zip_close(archive);

        return nullptr;
    }

    zfile->archive = archive;
    zfile->filename = IncRef((String *) args[0]);
    zfile->mode = IncRef((String *) args[1]);
    zfile->compression_method = (int) zip_method;
    zfile->is_open = true;

    new(&zfile->lock) argon::vm::sync::RecursiveSharedMutex();

    return (ArObject *) zfile;
}

ARGON_METHOD(zipfile_close, close,
             "Close the ZIP file.\n",
             nullptr, false, false) {
    auto *self = (ZipFile *) _self;

    std::unique_lock _(self->lock);

    if (self->is_open) {
        int result = zip_close(self->archive);

        if (result != 0) {
            ErrorFormat(kZipFileError[0], kZipFileError[1], zip_strerror(self->archive));

            return nullptr;
        }

        self->is_open = false;
    }

    return ARGON_NIL_VALUE;
}

ARGON_METHOD(zipfile_extract, extract,
             "Extract a member from the archive to the current working directory.\n"
             "\n"
             "- Parameter member: Filename of the member to extract.\n"
             "- KWParameters:\n"
             "  - path: A directory to extract to. The current working directory will be used if not specified.\n"
             "- Returns: The path to the extracted file.\n",
             "s: member", false, true) {
    auto *self = (ZipFile *) _self;

    String *path;
    if (!KParamLookupStr((Dict *) kwargs, "path", &path, "", nullptr))
        return nullptr;

    auto *fullpath = ExtractFile(self, (String *) args[0], path);

    Release(path);

    return (ArObject *) fullpath;
}

ARGON_METHOD(zipfile_extractall, extractall,
             "Extract all members from the archive to the current working directory.\n"
             "\n"
             "- KWParameters:\n"
             "  - path: A directory to extract to. The current working directory will be used if not specified.\n"
             "  - members: A list of members to extract. All members will be extracted if not specified.\n",
             nullptr, false, true) {
    auto *self = (ZipFile *) _self;
    ArObject *members;
    String *path;

    if (!KParamLookupStr((Dict *) kwargs, "path", &path, "", nullptr))
        return nullptr;

    if (!KParamLookup((Dict *) kwargs, "members", nullptr, &members, nullptr, true))
        return nullptr;

    if (members == nullptr) {
        auto num_entries = zip_get_num_entries(self->archive, 0);
        for (zip_int64_t i = 0; i < num_entries; i++) {
            auto *name = zip_get_name(self->archive, i, 0);
            if (name == nullptr) {
                Release(path);

                ErrorFormat(kZipFileError[0], kZipFileError[18], zip_strerror(self->archive));

                return nullptr;
            }

            auto ar_name = StringNew(name);
            if (ar_name == nullptr) {
                Release(path);

                return nullptr;
            }

            if (!ExtractFile(self, ar_name, path)) {
                Release(ar_name);
                Release(path);

                return nullptr;
            }

            Release(ar_name);
        }

        Release(path);

        return ARGON_NIL_VALUE;
    }

    auto *iter = IteratorGet(members, false);
    if (iter == nullptr) {
        Release(path);

        return nullptr;
    }

    ArObject *item;
    while ((item = IteratorNext(iter)) != nullptr) {
        if (!AR_TYPEOF(item, type_string_)) {
            ErrorFormat(kTypeError[0], kTypeError[2], type_string_->name, AR_TYPE_QNAME(item));

            Release(path);
            Release(item);
            Release(iter);

            return nullptr;
        }

        if (!ExtractFile(self, (String *) item, path)) {
            Release(item);
            Release(iter);
            Release(path);

            return nullptr;
        }

        Release(item);
    }

    Release(iter);
    Release(path);

    return ARGON_NIL_VALUE;
}

ARGON_METHOD(zipfile_mkdir, mkdir,
             "Create a directory inside the ZIP archive.\n"
             "\n"
             "- Parameter dirname: Name of the directory to create.\n"
             "- KWParameters:\n"
             "  - mode: Unix permission mode (default: 0o777 & ~umask).\n",
             "s: dirname", false, true) {
    auto *self = (ZipFile *) _self;
    auto *dir = (String *) args[0];

    IntegerUnderlying mode;

    if (!StringEndswith(dir, "/")) {
        dir = StringConcat(dir, "/", 1);
        if (dir == nullptr)
            return nullptr;
    } else
        IncRef(dir);

    if (!KParamLookupInt((Dict *) kwargs, "mode", &mode, 0755))
        return nullptr;

    mode &= 0777;

    std::unique_lock _(self->lock);

    if (!self->is_open) {
        ErrorFormat(kZipFileError[0], kZipFileError[15]);

        return nullptr;
    }

    auto *src = zip_source_buffer(self->archive, nullptr, 0, 0);
    if (src == nullptr) {
        Release(dir);

        ErrorFormat(kZipFileError[0], kZipFileError[2], zip_strerror(self->archive));
        return nullptr;
    }

    auto index = zip_file_add(self->archive, (const char *) ARGON_RAW_STRING(dir), src,
                              ZIP_FL_OVERWRITE | ZIP_FL_ENC_UTF_8);
    if (index < 0) {
        Release(dir);

        zip_source_free(src);

        ErrorFormat(kZipFileError[0], kZipFileError[3], zip_strerror(self->archive));
        return nullptr;
    }

    // Set file attributes (including permissions)
    zip_uint32_t attr = (mode << 16) | ZIP_OPSYS_UNIX;
    if (zip_file_set_external_attributes(self->archive, index, 0, ZIP_OPSYS_UNIX, attr) < 0) {
        Release(dir);

        ErrorFormat(kZipFileError[0], kZipFileError[4], zip_strerror(self->archive));
        return nullptr;
    }

    // Set modification time to current time
    auto now = time(nullptr);
    if (zip_file_set_mtime(self->archive, index, now, 0) < 0) {
        Release(dir);

        ErrorFormat(kZipFileError[0], kZipFileError[5], zip_strerror(self->archive));
        return nullptr;
    }

    Release(dir);

    return ARGON_NIL_VALUE;
}

ARGON_METHOD(zipfile_namelist, namelist,
             "Return a list of archive members by name.\n"
             "\n"
             "- Returns: A list of filenames in the archive.\n",
             nullptr, false, false) {
    auto *self = (ZipFile *) _self;

    std::unique_lock _(self->lock);

    if (!self->is_open) {
        ErrorFormat(kZipFileError[0], kZipFileError[15]);

        return nullptr;
    }

    auto num_entries = zip_get_num_entries(self->archive, 0);

    List *name_list;
    if ((name_list = ListNew(num_entries)) == nullptr)
        return nullptr;

    for (zip_int64_t i = 0; i < num_entries; i++) {
        const char *name = zip_get_name(self->archive, i, 0);
        if (name == nullptr)
            continue;

        String *str_name = StringNew(name);
        if (str_name == nullptr || !ListAppend(name_list, (ArObject *) str_name)) {
            Release(str_name);
            Release(name_list);

            return nullptr;
        }

        Release(str_name);
    }

    return (ArObject *) name_list;
}

ARGON_METHOD(zipfile_read, read,
             "Return the bytes of the file in the archive.\n"
             "\n"
             "- Parameter name: Name of the file in the archive.\n"
             "- Returns: Bytes object of the file contents.\n",
             "s: name", false, false) {
    auto *self = (ZipFile *) _self;
    auto *filename = (const char *) ARGON_RAW_STRING((String *) args[0]);

    std::unique_lock _(self->lock);

    if (!self->is_open) {
        ErrorFormat(kZipFileError[0], kZipFileError[15]);

        return nullptr;
    }

    auto *file = zip_fopen(self->archive, filename, 0);
    if (file == nullptr) {
        ErrorFormat(kValueError[0], "file '%s' not found in archive", filename);
        return nullptr;
    }

    zip_stat_t stat;
    if (zip_stat(self->archive, filename, 0, &stat) != 0) {
        zip_fclose(file);

        ErrorFormat(kZipFileError[0], kZipFileError[6], filename);
        return nullptr;
    }

    auto *content = BytesNew(stat.size, true, false, false);
    if (content == nullptr) {
        zip_fclose(file);

        return nullptr;
    }

    zip_int64_t read_bytes = zip_fread(file, content->view.buffer, stat.size);

    zip_fclose(file);

    if (read_bytes < 0 || (zip_uint64_t) read_bytes != stat.size) {
        Release(content);

        ErrorFormat(kZipFileError[0], kZipFileError[7], filename);
        return nullptr;
    }

    return (ArObject *) content;
}

ARGON_METHOD(zipfile_testzip, testzip,
             "Test the validity of the zip file.\n"
             "\n"
             "- Returns: The name of the first corrupt file in the archive, or nil if the zip file is valid.\n",
             nullptr, false, false) {
    auto *self = (ZipFile *) _self;
    char *buffer;

    int buflen = 1024 * 1024;

    zip_stat_t sb;

    std::unique_lock _(self->lock);

    if (!self->is_open) {
        ErrorFormat(kZipFileError[0], kZipFileError[15]);

        return nullptr;
    }

    // Alloc 1MB of buffer
    if ((buffer = (char *) argon::vm::memory::Alloc(buflen)))
        return nullptr;

    auto num_entries = zip_get_num_entries(self->archive, 0);
    for (zip_uint64_t i = 0; i < num_entries; i++) {
        if (zip_stat_index(self->archive, i, 0, &sb) != 0) {
            argon::vm::memory::Free(buffer);

            ErrorFormat(kZipFileError[0], kZipFileError[6], zip_strerror(self->archive));

            return nullptr;
        }

        auto *filename = sb.name;

        // Skip directories
        if (filename[strlen(filename) - 1] == '/')
            continue;

        auto *zf = zip_fopen_index(self->archive, i, 0);
        if (zf == nullptr) {
            argon::vm::memory::Free(buffer);

            ErrorFormat(kZipFileError[0], kZipFileError[8], zip_strerror(self->archive));

            return nullptr;
        }

        auto crc_computed = crc32(0L, Z_NULL, 0);

        zip_int64_t bytes_read;
        while ((bytes_read = zip_fread(zf, buffer, buflen)) > 0)
            crc_computed = crc32(crc_computed, (const Bytef *) buffer, bytes_read);

        if (bytes_read < 0) {
            argon::vm::memory::Free(buffer);

            ErrorFormat(kZipFileError[0], kZipFileError[9], zip_file_strerror(zf));

            zip_fclose(zf);

            return nullptr;
        }

        zip_fclose(zf);

        if (crc_computed != sb.crc)
            return (ArObject *) StringNew(filename);
    }

    argon::vm::memory::Free(buffer);

    return ARGON_NIL_VALUE;
}

ARGON_METHOD(zipfile_write, write,
             "Write a file into the archive.\n"
             "\n"
             "- Parameter filename: Path to the file to add.\n"
             "- KWParameters:\n"
             "  - arcname: Name of the file in the archive.\n"
             "  - level: Compression level (optional, default is -1 which means default compression).\n"
             "  - method: Compression method (optional, default is the ZipFile's compression method).\n",
             "s: filename", false, true) {
    struct stat st{};

    auto *self = (ZipFile *) _self;
    auto *filename = (const char *) ARGON_RAW_STRING((String *) args[0]);
    auto *arcname = filename;

    String *a_arcname;

    IntegerUnderlying c_method;
    IntegerUnderlying compress_level;

    bool default_arcname;

    if (!KParamLookupStr((Dict *) kwargs, "arcname", &a_arcname, nullptr, &default_arcname))
        return nullptr;

    if (!default_arcname)
        arcname = (const char *) ARGON_RAW_STRING(a_arcname);

    if (!KParamLookupInt((Dict *) kwargs, "method", &c_method, self->compression_method))
        return nullptr;

    if (!KParamLookupInt((Dict *) kwargs, "level", &compress_level, -1))
        return nullptr;

    std::unique_lock _(self->lock);

    if (!self->is_open) {
        ErrorFormat(kZipFileError[0], kZipFileError[15]);

        return nullptr;
    }

    if (stat(filename, &st) < 0) {
        ErrorFromErrno(errno);

        return nullptr;
    }

    // Create a zip source from the file
    zip_source_t *source = zip_source_file(self->archive, filename, 0, st.st_size);
    if (source == nullptr) {
        ErrorFormat(kZipFileError[0], kZipFileError[11], zip_strerror(self->archive));

        return nullptr;
    }

    // Add the file to the archive
    auto index = zip_file_add(self->archive, (const char *) arcname, source, ZIP_FL_OVERWRITE);
    if (index < 0) {
        zip_source_free(source);

        ErrorFormat(kZipFileError[0], kZipFileError[12], zip_strerror(self->archive));
        return nullptr;
    }

    // Set compression method
    if (zip_set_file_compression(self->archive, index, (int) c_method, compress_level) < 0) {
        ErrorFormat(kZipFileError[0], kZipFileError[13], zip_strerror(self->archive));
        return nullptr;
    }

    return ARGON_NIL_VALUE;
}

ARGON_METHOD(zipfile_writeraw, writeraw,
             "Write a bufferable object to the archive.\n"
             "\n"
             "- Parameters:\n"
             "  - arcname: Name for the file in the archive.\n"
             "  - data: The content to write to the archive.\n"
             "- KWParameters:\n"
             "  - level: Compression level (optional, default is -1 which means default compression).\n"
             "  - method: Compression method (optional, default is the ZipFile's compression method).\n",
             "s: arcname, : data", false, true) {
    ArBuffer buffer{};
    struct zip_stat zip_stat{};

    auto *self = (ZipFile *) _self;

    IntegerUnderlying c_method;
    IntegerUnderlying compress_level;

    if (!KParamLookupInt((Dict *) kwargs, "type", &c_method, 0))
        return nullptr;

    if (!KParamLookupInt((Dict *) kwargs, "level", &compress_level, -1))
        return nullptr;

    if (!BufferGet(args[1], &buffer, BufferFlags::READ))
        return nullptr;

    std::unique_lock _(self->lock);

    if (!self->is_open) {
        ErrorFormat(kZipFileError[0], kZipFileError[15]);

        return nullptr;
    }

    // Create a zip source from the buffer
    auto *source = zip_source_buffer(self->archive, buffer.buffer, buffer.length, 0);
    if (source == nullptr) {
        BufferRelease(&buffer);

        ErrorFormat(kZipFileError[0], kZipFileError[11], zip_strerror(self->archive));
        return nullptr;
    }

    // Add the data to the archive
    auto index = zip_file_add(self->archive,
                              (const char *) ARGON_RAW_STRING((String *) args[0]),
                              source, ZIP_FL_OVERWRITE);
    if (index < 0) {
        BufferRelease(&buffer);

        ErrorFormat(kZipFileError[0], kZipFileError[14], zip_strerror(self->archive));
        return nullptr;
    }

    // Set compression method and level
    if (zip_set_file_compression(self->archive, index, (int) c_method, (zip_uint32_t) compress_level) < 0) {
        BufferRelease(&buffer);

        ErrorFormat(kZipFileError[0], kZipFileError[13], zip_strerror(self->archive));
        return nullptr;
    }

    // Set file metadata
    zip_stat_init(&zip_stat);

    zip_stat.size = buffer.length;
    zip_stat.mtime = time(nullptr);

    if (zip_file_set_external_attributes(self->archive, index, 0, ZIP_OPSYS_UNIX, 0100644 << 16) < 0 ||
        zip_file_set_mtime(self->archive, index, zip_stat.mtime, 0) < 0) {
        BufferRelease(&buffer);

        ErrorFormat(kZipFileError[0], kZipFileError[15], zip_strerror(self->archive));
        return nullptr;
    }

    BufferRelease(&buffer);

    return ARGON_NIL_VALUE;
}

bool zipfile_dtor(ZipFile *self) {
    if (self->is_open) {
        zip_close(self->archive);
    }

    Release(self->filename);
    Release(self->mode);
    return true;
}

const FunctionDef zipfile_methods[] = {
        zipfile_zipfile,

        zipfile_close,
        zipfile_extract,
        zipfile_extractall,
        zipfile_mkdir,
        zipfile_namelist,
        zipfile_read,
        zipfile_testzip,
        zipfile_write,
        zipfile_writeraw,
        ARGON_METHOD_SENTINEL
};

const ObjectSlots zipfile_objslot = {
        zipfile_methods,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        -1
};

TypeInfo ZipFileType = {
        AROBJ_HEAD_INIT_TYPE,
        "ZipFile",
        nullptr,
        "ZipFile is used to manipulate ZIP archives. "
        "It provides methods for extracting files, adding new files, and testing the integrity of the archive.",
        sizeof(ZipFile),
        TypeInfoFlags::BASE,
        nullptr,
        (Bool_UnaryOp) zipfile_dtor,
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
        &zipfile_objslot,
        nullptr,
        nullptr,
        nullptr,
        nullptr
};
const TypeInfo *arlib::compressor::zipfile::type_zipfile_ = &ZipFileType;

const ModuleEntry zipfile_entries[] = {
        MODULE_EXPORT_TYPE(type_zipfile_),

        ARGON_MODULE_SENTINEL
};

bool ZipFileInit(Module *self) {
#define AddIntConstant(name)                                \
    do {                                                    \
        if (zip_compression_method_supported(name, 1)) {    \
            if(!ModuleAddIntConstant(self, #name, name))    \
                return false;                               \
        }                                                   \
    } while(0)

    AddIntConstant(ZIP_CM_BZIP2);
    AddIntConstant(ZIP_CM_DEFLATE);
    AddIntConstant(ZIP_CM_DEFLATE64);
    AddIntConstant(ZIP_CM_LZMA);
    AddIntConstant(ZIP_CM_STORE);

    return TypeInit((TypeInfo *) type_zipfile_, nullptr);
}

constexpr ModuleInit ModuleZipFile = {
        "zipfile",
        "This module provides tools for creating, reading, writing, and manipulating ZIP archives.",
        ARLIB_VERSION,
        zipfile_entries,
        ZipFileInit,
        nullptr
};

ARGON_MODULE_INIT(ModuleZipFile)
