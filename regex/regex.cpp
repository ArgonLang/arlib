// This source file is part of the Argon project.
//
// Licensed under the Apache License v2.0

#include <argon/vm/runtime.h>

#include <argon/vm/datatype/error.h>
#include <argon/vm/datatype/module.h>

#include <argon/vm/memory/memory.h>

#include <version.h>

#include <regex/regex.h>

using namespace argon::vm::datatype;
using namespace arlib::regex;

pcre2_general_context *arlib::regex::general_context = nullptr;

const ModuleEntry regex_entries[] = {
        MODULE_EXPORT_TYPE(type_pattern_),
        MODULE_EXPORT_TYPE(type_match_),

        ARGON_MODULE_SENTINEL
};

bool RegexInit(Module *self) {
#define AddIntConstant(name, value)                 \
    if(!ModuleAddIntConstant(self, name, value))    \
        return false

    // *** Pattern options ***
    AddIntConstant("PO_ANCHORED", PCRE2_ANCHORED);
    AddIntConstant("PO_ALLOW_EMPTY_CLASS", PCRE2_ALLOW_EMPTY_CLASS);
    AddIntConstant("PO_ALT_BSUX", PCRE2_ALT_BSUX);
    AddIntConstant("PO_ALT_CIRCUMFLEX", PCRE2_ALT_CIRCUMFLEX);
    AddIntConstant("PO_ALT_VERBNAMES", PCRE2_ALT_VERBNAMES);
    AddIntConstant("PO_AUTO_CALLOUT", PCRE2_AUTO_CALLOUT);
    AddIntConstant("PO_CASELESS", PCRE2_CASELESS);
    AddIntConstant("PO_DOLLAR_ENDONLY", PCRE2_DOLLAR_ENDONLY);
    AddIntConstant("PO_DOTALL", PCRE2_DOTALL);
    AddIntConstant("PO_DUPNAMES", PCRE2_DUPNAMES);
    AddIntConstant("PO_ENDANCHORED", PCRE2_ENDANCHORED);
    AddIntConstant("PO_EXTENDED", PCRE2_EXTENDED);
    AddIntConstant("PO_FIRSTLINE", PCRE2_FIRSTLINE);
    AddIntConstant("PO_LITERAL", PCRE2_LITERAL);
    AddIntConstant("PO_MATCH_INVALID_UTF", PCRE2_MATCH_INVALID_UTF);
    AddIntConstant("PO_MATCH_UNSET_BACKREF", PCRE2_MATCH_UNSET_BACKREF);
    AddIntConstant("PO_MULTILINE", PCRE2_MULTILINE);
    AddIntConstant("PO_NEVER_BACKSLASH_C", PCRE2_NEVER_BACKSLASH_C);
    AddIntConstant("PO_NEVER_UCP", PCRE2_NEVER_UCP);
    AddIntConstant("PO_NEVER_UTF", PCRE2_NEVER_UTF);
    AddIntConstant("PO_NO_AUTO_CAPTURE", PCRE2_NO_AUTO_CAPTURE);
    AddIntConstant("PO_NO_AUTO_POSSESS", PCRE2_NO_AUTO_POSSESS);
    AddIntConstant("PO_NO_DOTSTAR_ANCHOR", PCRE2_NO_DOTSTAR_ANCHOR);
    AddIntConstant("PO_NO_START_OPTIMIZE", PCRE2_NO_START_OPTIMIZE);
    AddIntConstant("PO_NO_UTF_CHECK", PCRE2_NO_UTF_CHECK);
    AddIntConstant("PO_UCP", PCRE2_UCP);
    AddIntConstant("PO_UNGREEDY", PCRE2_UNGREEDY);
    AddIntConstant("PO_USE_OFFSET_LIMIT", PCRE2_USE_OFFSET_LIMIT);
    AddIntConstant("PO_UTF", PCRE2_UTF);

    // *** Match options ***
    AddIntConstant("MO_ANCHORED", PCRE2_ANCHORED);
    AddIntConstant("MO_COPY_MATCHED_SUBJECT", PCRE2_COPY_MATCHED_SUBJECT);
    AddIntConstant("MO_ENDANCHORED", PCRE2_ENDANCHORED);
    AddIntConstant("MO_NOTBOL", PCRE2_NOTBOL);
    AddIntConstant("MO_NOTEOL", PCRE2_NOTEOL);
    AddIntConstant("MO_NOTEMPTY", PCRE2_NOTEMPTY);
    AddIntConstant("MO_NOTEMPTY_ATSTART", PCRE2_NOTEMPTY_ATSTART);
    AddIntConstant("MO_NO_JIT", PCRE2_NO_JIT);
    AddIntConstant("MO_NO_UTF_CHECK", PCRE2_NO_UTF_CHECK);
    AddIntConstant("MO_PARTIAL_HARD", PCRE2_PARTIAL_HARD);
    AddIntConstant("MO_PARTIAL_SOFT", PCRE2_PARTIAL_SOFT);

    if (!TypeInit((TypeInfo *) type_pattern_, nullptr))
        return false;

    if (!TypeInit((TypeInfo *) type_match_, nullptr))
        return false;

    assert(general_context == nullptr);

    general_context = pcre2_general_context_create(
            [](size_t len, [[maybe_unused]]void *data) -> void * {
                return argon::vm::memory::Alloc(len);
            },
            [](void *ptr, [[maybe_unused]]void *data) {
                argon::vm::memory::Free(ptr);
            }, nullptr);

    if (general_context == nullptr)
        return false;

    return true;
#undef AddIntConstant
}

bool RegexFini([[maybe_unused]]Module *self) {
    pcre2_general_context_free(general_context);
    general_context = nullptr;

    return true;
}

constexpr ModuleInit ModuleRegex = {
        "regex",
        "This module provides Perl-like regex support.",
        ARLIB_VERSION,
        regex_entries,
        RegexInit,
        RegexFini
};

ARGON_MODULE_INIT(ModuleRegex)

void arlib::regex::ErrorFromPCRE(int ecode) {
    unsigned char ebuf[128]{};
    Error *err;

    int length = pcre2_get_error_message(ecode, ebuf, 128);
    if (length == PCRE2_ERROR_BADDATA)
        err = ErrorNew(kRegexError[0], kRegexError[1]);
    else
        err = ErrorNew(kRegexError[0], (const char *) ebuf);

    argon::vm::Panic((ArObject *) err);

    Release(err);
}
