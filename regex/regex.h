// This source file is part of the Argon project.
//
// Licensed under the Apache License v2.0

#ifndef ARLIB_REGEX_REGEX_H_
#define ARLIB_REGEX_REGEX_H_

#define PCRE2_CODE_UNIT_WIDTH 8

#include <pcre2.h>

#include <argon/vm/datatype/arobject.h>
#include <argon/vm/datatype/tuple.h>

namespace arlib::regex {
    constexpr const char *kRegexError[] = {
            (const char *) "RegexError",
            (const char *) "unknown error",
    };

    struct MatchGroup {
        size_t start;
        size_t end;

        argon::vm::datatype::ArObject *chunk;
    };

    struct Match {
        AROBJ_HEAD;

        MatchGroup *groups;

        unsigned int g_count;

        size_t start;
        size_t end;
    };
    extern const argon::vm::datatype::TypeInfo *type_match_;

    struct Pattern {
        AROBJ_HEAD;

        argon::vm::datatype::ArObject *pattern;

        pcre2_code *code;
        pcre2_compile_context *context;
    };
    extern const argon::vm::datatype::TypeInfo *type_pattern_;

    extern pcre2_general_context *general_context;

    Match *Find(const unsigned char *buffer, size_t length, const argon::vm::datatype::TypeInfo *b_info,
                const Pattern *pattern, unsigned int options, bool store_match);

    Match *MatchNew(const argon::vm::datatype::TypeInfo *b_info, const unsigned char *buffer, const size_t *ovector,
                    unsigned int matches);

    Pattern *PatternNew(argon::vm::datatype::ArObject *pattern, unsigned int options);

    argon::vm::datatype::Tuple *FindAll(const unsigned char *buffer, size_t length,
                                        const argon::vm::datatype::TypeInfo *b_info, const Pattern *pattern,
                                        unsigned int options, bool store_match);

    void ErrorFromPCRE(int ecode);

} // namespace arlib::regex

#endif // !ARLIB_REGEX_REGEX_H_
