// This source file is part of the Argon project.
//
// Licensed under the Apache License v2.0

#include <argon/vm/datatype/boolean.h>
#include <argon/vm/datatype/bytes.h>
#include <argon/vm/datatype/error.h>
#include <argon/vm/datatype/integer.h>
#include <argon/vm/datatype/tuple.h>

#include <regex/regex.h>

using namespace argon::vm::datatype;
using namespace arlib::regex;

ARGON_METHOD(match_group, group,
             "Returns a 3-tuple containing the requested subgroup.\n"
             "\n"
             "- Parameter group: Subgroup index (if zero returns the entire matching string).\n"
             "- Returns: 3-tuple (start, stop, match).\n",
             "i: group", false, false) {
    auto *self = (const Match *) _self;
    IntegerUnderlying index;

    index = ((const Integer *) args[0])->sint;

    if (index < 0 || index >= self->g_count) {
        ErrorFormat(kValueError[0], "%d no such group", index);
        return nullptr;
    }

    return (ArObject *) TupleNew("IIO",
                                 self->groups[index].start,
                                 self->groups[index].end,
                                 self->groups[index].chunk);
}

ARGON_METHOD(match_match, match,
             "Returns a n-tuple containing the requested submatch.\n"
             "\n"
             "- Parameter ...group: Subgroups index.\n"
             "- Returns: n-tuple with the required submatches.\n",
             "i: group", true, false) {
    auto *self = (const Match *) _self;
    Tuple *ret;

    if ((ret = TupleNew(argc)) == nullptr)
        return nullptr;

    for (ArSize i = 0; i < argc; i++) {
        auto *tmp = ((const Integer *) args[i]);

        if (!AR_TYPEOF(tmp, type_int_)) {
            ErrorFormat(kTypeError[0], kTypeError[2], type_int_->name, AR_TYPE_NAME(tmp));

            Release(ret);
            return nullptr;
        }

        auto index = tmp->sint;
        if (index < 0 || index >= self->g_count) {
            ErrorFormat(kValueError[0], "%d no such group", index);

            Release(ret);
            return nullptr;
        }

        TupleInsert(ret, self->groups[index].chunk, i);
    }

    return (ArObject *) ret;
}

const FunctionDef match_methods[] = {
        match_group,
        match_match,
        ARGON_METHOD_SENTINEL
};

const MemberDef match_members[] = {
        ARGON_MEMBER("start", MemberType::LONG, offsetof(Match, start), true),
        ARGON_MEMBER("end", MemberType::LONG, offsetof(Match, end), true),
        ARGON_MEMBER("groups", MemberType::LONG, offsetof(Match, g_count), true),
        ARGON_MEMBER_SENTINEL
};

const ObjectSlots match_objslot = {
        match_methods,
        match_members,
        nullptr,
        nullptr,
        nullptr,
        -1
};

ArObject *match_get_item(Match *self, ArObject *index) {
    IntegerUnderlying idx;

    if (!AR_TYPEOF(index, type_int_)){
        ErrorFormat(kTypeError[0], kTypeError[2], type_int_->name, AR_TYPE_NAME(index));

        return nullptr;
    }

    idx = ((const Integer *) index)->sint;
    if (idx < 0 || idx >= self->g_count) {
        ErrorFormat(kValueError[0], "%d no such group", index);

        return nullptr;
    }

    return IncRef(self->groups[idx].chunk);
}

ArSize match_length(const Match *self) {
    return self->g_count;
}

const SubscriptSlots match_subscript = {
        (ArSize_UnaryOp )match_length,
        (BinaryOp)match_get_item,
        nullptr,
        nullptr,
        nullptr,
        nullptr
};

ArObject *match_compare(const Match *self, ArObject *other, CompareMode mode) {
    const auto *o = (Match *) other;

    if (!AR_SAME_TYPE(self, other) || mode != CompareMode::EQ)
        return nullptr;

    if (self == o)
        return BoolToArBool(true);

    return BoolToArBool(self->start == o->start &&
                        self->end == o->end &&
                        self->g_count == o->g_count &&
                        Equal(self->groups[0].chunk, o->groups[0].chunk));
}

ArObject *match_repr(const Match *self) {
    ArObject *ret;

    ret = (ArObject *) StringFormat("<%s -- start: %d, end: %d, groups: %d>",
                                    AR_TYPE_NAME(self),
                                    self->start,
                                    self->end,
                                    self->g_count);

    return ret;
}

bool match_is_true(const Match *self) {
    return self->end != 0;
}

bool match_dtor(const Match *self) {
    for (int i = 0; i < self->g_count; i++)
        Release(self->groups[i].chunk);

    argon::vm::memory::Free(self->groups);
    return true;
}

TypeInfo MatchType = {
        AROBJ_HEAD_INIT_TYPE,
        "Match",
        nullptr,
        "The Match object contains information about a successful match of a Pattern "
        "object against a string. It provides access to the matched groups and various properties of the match.",
        sizeof(Match),
        TypeInfoFlags::BASE,
        nullptr,
        (Bool_UnaryOp) match_dtor,
        nullptr,
        nullptr,
        (Bool_UnaryOp) match_is_true,
        (CompareOp) match_compare,
        (UnaryConstOp) match_repr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        &match_objslot,
        &match_subscript,
        nullptr,
        nullptr,
        nullptr
};
const TypeInfo *arlib::regex::type_match_ = &MatchType;

Match *arlib::regex::Find(const unsigned char *buffer, size_t length, const argon::vm::datatype::TypeInfo *b_info,
                          const Pattern *pattern, unsigned int options, bool store_match) {
    Match *match;

    int err;

    auto *match_data = pcre2_match_data_create_from_pattern(pattern->code, general_context);
    if (match_data == nullptr) {
        // if nullptr -> ENOMEM!
        return nullptr;
    }

    auto ovector = pcre2_get_ovector_pointer(match_data);
    ovector[1] = 0;

    err = pcre2_match(pattern->code,
                      buffer,
                      length,
                      0,
                      options,
                      match_data,
                      nullptr);

    if (err < 0 && err != PCRE2_ERROR_NOMATCH) {
        ErrorFromPCRE(err);

        pcre2_match_data_free(match_data);
        return nullptr;
    }

    match = MatchNew(b_info, store_match ? buffer : nullptr, ovector, pcre2_get_ovector_count(match_data));

    pcre2_match_data_free(match_data);

    return match;
}

Match *arlib::regex::MatchNew(const argon::vm::datatype::TypeInfo *b_info, const unsigned char *buffer,
                              const size_t *ovector, unsigned int matches) {
    auto *match = MakeObject<Match>(&MatchType);
    if (match == nullptr)
        return nullptr;

    match->groups = (MatchGroup *) argon::vm::memory::Calloc(matches * sizeof(MatchGroup));
    if (match->groups == nullptr) {
        Release(match);
        return nullptr;
    }

    match->g_count = matches;
    match->start = 0;
    match->end = 0;

    if (ovector[1] == 0)
        return match;

    for (int i = 0; i < match->g_count; i++) {
        match->groups[i].start = ovector[2 * i];
        match->groups[i].end = ovector[(2 * i) + 1];

        if (buffer != nullptr) {
            if (b_info == type_string_) {
                match->groups[i].chunk = (ArObject *) StringNew(buffer + match->groups[i].start,
                                                                match->groups[i].end - match->groups[i].start);
            } else {
                match->groups[i].chunk = (ArObject *) BytesNew(buffer + match->groups[i].start,
                                                               match->groups[i].end - match->groups[i].start,
                                                               true);
            }

            if (match->groups[i].chunk == nullptr) {
                Release(match);
                return nullptr;
            }
        }
    }

    match->start = match->groups[0].start;
    match->end = match->groups[0].end;

    return match;
}

Tuple *arlib::regex::FindAll(const unsigned char *buffer, size_t length, const argon::vm::datatype::TypeInfo *b_info,
                             const Pattern *pattern, unsigned int options, bool store_match) {
    List *m_list;

    int err;

    if ((m_list = ListNew()) == nullptr)
        return nullptr;

    auto *match_data = pcre2_match_data_create_from_pattern(pattern->code, general_context);
    if (match_data == nullptr) {
        // if nullptr -> ENOMEM!
        Release(m_list);
        return nullptr;
    }

    auto start_offset = (size_t) 0;
    auto ov_count = pcre2_get_ovector_count(match_data);
    auto ovector = pcre2_get_ovector_pointer(match_data);

    do {
        ovector[1] = 0;

        err = pcre2_match(pattern->code,
                          buffer,
                          length,
                          start_offset,
                          options,
                          match_data,
                          nullptr);

        if (err < 0 && err != PCRE2_ERROR_NOMATCH) {
            ErrorFromPCRE(err);

            pcre2_match_data_free(match_data);

            Release(m_list);
            return nullptr;
        }

        if (err != PCRE2_ERROR_NOMATCH) {
            auto *match = MatchNew(b_info, store_match ? buffer : nullptr, ovector, ov_count);
            if (match == nullptr) {
                pcre2_match_data_free(match_data);

                Release(m_list);

                return nullptr;
            }

            if (!ListAppend(m_list, (ArObject *) match)) {
                pcre2_match_data_free(match_data);

                Release(match);
                Release(m_list);

                return nullptr;
            }

            Release(match);
        }

        start_offset = ovector[1];
    } while (err != PCRE2_ERROR_NOMATCH && start_offset < length);

    pcre2_match_data_free(match_data);

    auto *ret = TupleConvertList(&m_list);

    Release(m_list);

    return ret;
}
