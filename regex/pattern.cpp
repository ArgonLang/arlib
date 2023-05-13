// This source file is part of the Argon project.
//
// Licensed under the Apache License v2.0

#include <argon/vm/datatype/arstring.h>
#include <argon/vm/datatype/boolean.h>
#include <argon/vm/datatype/dict.h>
#include <argon/vm/datatype/integer.h>
#include <argon/vm/datatype/bytes.h>

#include <argon/vm/runtime.cpp>

#include <regex/regex.h>

using namespace argon::vm::datatype;
using namespace arlib::regex;

ARGON_FUNCTION(pattern_pattern, Pattern,
               "Compile a regular expression pattern into a Pattern object.\n"
               "\n"
               "- Parameters pattern: Regex pattern.\n"
               "- KWParameters:\n"
               "  - options: Options flag.\n"
               "- Returns: Pattern object.\n",
               "sx: pattern", false, true) {
    unsigned int opt;

    opt = (unsigned int) DictLookupInt((Dict *) kwargs, "options", 0);

    return (ArObject *) PatternNew(args[0], opt);
}

ARGON_METHOD(pattern_find, find,
             "Scan through 'subject' looking for the first location where the regular expression pattern produces a match.\n"
             "\n"
             "- Parameter subject: The subject which you want to search for the pattern.\n"
             "- KParameters:\n"
             "  - store: Boolean indicating whether to extract and store the substring inside the match object.\n"
             "- Returns: Match object.\n",
             "sx: subject", false, true) {
    ArBuffer buffer{};
    ArObject *ret;

    bool store;

    if (!BufferGet(args[0], &buffer, BufferFlags::READ))
        return nullptr;

    store = DictLookupIsTrue((Dict *) kwargs, "store", true);

    ret = (ArObject *) Find(buffer.buffer,
                            buffer.length,
                            AR_GET_TYPE(args[0]),
                            (Pattern *) _self,
                            0,
                            store);

    BufferRelease(&buffer);

    return ret;
}

ARGON_METHOD(pattern_findall, findall,
             "Return all non-overlapping matches of pattern in 'subject' as a tuple.\n"
             "\n"
             "- Parameter subject: The subject which you want to search for the pattern.\n"
             "- KParameters:\n"
             "  - store: Boolean indicating whether to extract and store the substring inside the match object.\n"
             "- Returns: Tuple containing zero or more matches.\n",
             "sx: subject", false, true) {
    ArBuffer buffer{};
    ArObject *ret;

    bool store;

    if (!BufferGet(args[0], &buffer, BufferFlags::READ))
        return nullptr;

    store = DictLookupIsTrue((Dict *) kwargs, "store", true);

    ret = (ArObject *) FindAll(buffer.buffer,
                               buffer.length,
                               AR_GET_TYPE(args[0]),
                               (Pattern *) _self,
                               0,
                               store);

    BufferRelease(&buffer);

    return ret;
}

ARGON_METHOD(pattern_replace, replace,
             "Return an object obtained by replacing the leftmost non-overlapping occurrences of pattern in 'subject' "
             "by the replacement 'replace'.\n"
             "\n"
             "- Parameters:\n"
             "  - subject: The subject which you want to search for the pattern.\n"
             "  - replace: Value to replace.\n"
             "- KParameters:\n"
             "  - count: Number specifying how many occurrences of the old value you want to replace (-1 for all).\n"
             "- Returns: Object of type 'subject' (or Bytes) where a specified value is replaced.\n",
             "sx: subject, sx: replace", false, true) {
    ArBuffer b_subj{};
    ArBuffer b_replace{};

    auto *self = (const Pattern *) _self;

    ArObject *ret;

    unsigned char *output;
    unsigned char *cursor;
    const unsigned char *subj_off;

    ArSize output_length;
    IntegerUnderlying count;

    if (!BufferGet(args[0], &b_subj, BufferFlags::READ))
        return nullptr;

    if (!BufferGet(args[1], &b_replace, BufferFlags::READ)) {
        BufferRelease(&b_subj);
        return nullptr;
    }

    count = DictLookupInt((Dict *) kwargs, "count", -1);

    auto *matches = FindAll(b_subj.buffer, b_subj.length, AR_GET_TYPE(args[0]), self, 0, false);
    if (matches == nullptr) {
        BufferRelease(&b_subj);
        BufferRelease(&b_replace);
        return nullptr;
    }

    // Calculate size
    output_length = b_subj.length;
    for (ArSize i = 0; i < matches->length; i++) {
        auto *match = (const Match *) matches->objects[i];

        if (i >= count && count >= 0)
            break;

        output_length -= match->end - match->start;
    }

    if (count >= 0 && count < matches->length)
        output_length += b_replace.length * count;
    else
        output_length += b_replace.length * matches->length;

    if (AR_TYPEOF(args[0], type_string_))
        output_length += 1; // \0

    if ((output = (unsigned char *) argon::vm::memory::Alloc(output_length)) == nullptr) {
        Release(matches);

        BufferRelease(&b_subj);
        BufferRelease(&b_replace);
        return nullptr;
    }

    cursor = output;
    subj_off = b_subj.buffer;

    // Make replace
    for (ArSize i = 0; i < matches->length; i++) {
        auto *match = (const Match *) matches->objects[i];

        if (i >= count && count >= 0)
            break;

        cursor = (unsigned char *) argon::vm::memory::MemoryCopy(cursor, subj_off,
                                                                 (b_subj.buffer + match->start) - subj_off);

        cursor = (unsigned char *) argon::vm::memory::MemoryCopy(cursor, b_replace.buffer, b_replace.length);

        subj_off = b_subj.buffer + match->end;
    }

    argon::vm::memory::MemoryCopy(cursor, subj_off, (b_subj.buffer + b_subj.length) - subj_off);

    Release(matches);

    BufferRelease(&b_subj);
    BufferRelease(&b_replace);

    if (AR_TYPEOF(args[0], type_string_)) {
        output[output_length - 1] = '\0';

        ret = (ArObject *) StringNewHoldBuffer(output, output_length - 1);
    } else
        ret = (ArObject *) BytesNewHoldBuffer(output, output_length, output_length, false);

    if (ret == nullptr)
        argon::vm::memory::Free(output);

    return ret;
}

ARGON_METHOD(pattern_split, split,
             "Split 'subject' by the occurrences of pattern.\n"
             "\n"
             "- Parameter subject: The subject which you want to search for the pattern.\n"
             "- KParameters:\n"
             "  - count: Specifies how many splits to do.\n"
             "- Returns: List of split elements.\n",
             "sx: subject", false, true) {
    ArBuffer b_subj{};

    auto *self = (const Pattern *) _self;

    ArObject *tmp;
    List *ret;

    IntegerUnderlying count;

    if (!BufferGet(args[0], &b_subj, BufferFlags::READ))
        return nullptr;

    if ((ret = ListNew()) == nullptr) {
        BufferRelease(&b_subj);
        return nullptr;
    }

    count = DictLookupInt((Dict *) kwargs, "count", -1);

    auto *matches = FindAll(b_subj.buffer, b_subj.length, AR_GET_TYPE(args[0]), self, 0, false);
    if (matches == nullptr) {
        BufferRelease(&b_subj);

        Release(ret);

        return nullptr;
    }

    auto cursor = b_subj.buffer;

    for (ArSize i = 0; i < matches->length; i++) {
        auto *match = (const Match *) matches->objects[i];

        if (i >= count && count >= 0)
            break;

        if (AR_TYPEOF(args[0], type_string_))
            tmp = (ArObject *) StringNew(cursor, (b_subj.buffer + match->start) - cursor);
        else
            tmp = (ArObject *) BytesNew(cursor, (b_subj.buffer + match->start) - cursor);

        if (tmp == nullptr) {
            BufferRelease(&b_subj);
            Release(matches);
            Release(ret);
            return nullptr;
        }

        cursor = b_subj.buffer + match->end;

        if (!ListAppend(ret, tmp)) {
            BufferRelease(&b_subj);
            Release(tmp);
            Release(matches);
            Release(ret);
            return nullptr;
        }

        Release(tmp);
    }

    if (AR_TYPEOF(args[0], type_string_))
        tmp = (ArObject *) StringNew(cursor, (b_subj.buffer + b_subj.length) - cursor);
    else
        tmp = (ArObject *) BytesNew(cursor, (b_subj.buffer + b_subj.length) - cursor);

    BufferRelease(&b_subj);

    if (tmp == nullptr) {
        Release(matches);
        Release(ret);
        return nullptr;
    }

    if (!ListAppend(ret, tmp)) {
        Release(tmp);
        Release(matches);
        Release(ret);
        return nullptr;
    }

    Release(tmp);

    Release(matches);

    return (ArObject *) ret;
}

const FunctionDef pattern_methods[] = {
        pattern_pattern,

        pattern_find,
        pattern_findall,
        pattern_replace,
        pattern_split,
        ARGON_METHOD_SENTINEL
};

const MemberDef pattern_members[] = {
        ARGON_MEMBER("pattern", MemberType::OBJECT, offsetof(Pattern, pattern), true),
        ARGON_MEMBER_SENTINEL
};

const ObjectSlots pattern_objslot = {
        pattern_methods,
        pattern_members,
        nullptr,
        nullptr,
        nullptr,
        -1
};

ArObject *pattern_compare(const ArObject *self, const ArObject *other, CompareMode mode) {
    const auto *o = (const Pattern *) other;

    if (!AR_SAME_TYPE(self, other) || mode != CompareMode::EQ)
        return nullptr;

    if (self == other)
        return BoolToArBool(true);

    return Compare(((const Pattern *) self)->pattern, o->pattern, mode);
}

ArObject *pattern_repr(const Pattern *self) {
    ArObject *ret;

    auto *r = (String *) Repr(self->pattern);
    if (r == nullptr)
        return nullptr;

    ret = (ArObject *) StringFormat("regex.%s(%s)", AR_TYPE_NAME(self), ARGON_RAW_STRING(r));

    Release(r);
    return ret;
}

bool pattern_dtor(Pattern *self) {
    Release(self->pattern);

    if (self->code != nullptr)
        pcre2_code_free(self->code);

    if (self->context != nullptr)
        pcre2_compile_context_free(self->context);

    return true;
}

TypeInfo PatternType = {
        AROBJ_HEAD_INIT_TYPE,
        "Pattern",
        nullptr,
        nullptr,
        sizeof(Pattern),
        TypeInfoFlags::BASE,
        nullptr,
        (Bool_UnaryOp) pattern_dtor,
        nullptr,
        nullptr,
        nullptr,
        pattern_compare,
        (UnaryConstOp) pattern_repr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        &pattern_objslot,
        nullptr,
        nullptr,
        nullptr,
        nullptr
};
const TypeInfo *arlib::regex::type_pattern_ = &PatternType;

Pattern *arlib::regex::PatternNew(ArObject *pattern, unsigned int options) {
    ArBuffer buffer{};

    Pattern *p_obj;

    size_t eoffset;
    int ecode;

    if (!BufferGet(pattern, &buffer, BufferFlags::READ))
        return nullptr;

    if ((p_obj = MakeObject<Pattern>(&PatternType)) == nullptr) {
        BufferRelease(&buffer);
        return nullptr;
    }

    p_obj->pattern = IncRef(pattern);
    p_obj->context = nullptr;
    p_obj->code = nullptr;

    if ((p_obj->context = pcre2_compile_context_create(general_context)) == nullptr) {
        BufferRelease(&buffer);
        Release(p_obj);
        return nullptr;
    }

    p_obj->code = pcre2_compile(buffer.buffer, buffer.length, options, &ecode, &eoffset, p_obj->context);
    if (p_obj->code == nullptr) {
        ErrorFromPCRE(ecode);

        BufferRelease(&buffer);
        Release(p_obj);
        return nullptr;
    }

    BufferRelease(&buffer);

    return p_obj;
}