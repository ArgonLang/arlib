// This source file is part of the Argon project.
//
// Licensed under the Apache License v2.0

#include <argon/vm/runtime.h>

#include <argon/vm/datatype/module.h>
#include <argon/vm/datatype/nil.h>

#include <version.h>

#include <ssl/ssl.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#undef CONST // Windows MACRO
#undef ERROR // Windows MACRO

using namespace argon::vm::datatype;
using namespace arlib::ssl;

// Prototypes
static Tuple *TupleX509Name(const X509_NAME *name);

#ifdef _ARGON_PLATFORM_WINDOWS

ARGON_FUNCTION(ssl_enumcerts, enumcerts,
               "Retrieve certificates from Windows’ system cert store.\n"
               "\n"
               "- Parameter store_name: May be one of \"CA\", \"ROOT\" or \"MY\"\n"
               "- Returns: List of (cert_bytes, encoding_type, trust) tuples.\n",
               "s: store_name", false, false) {
    return (ArObject *) EnumWindowsCert((const char *) ARGON_RAW_STRING((String *) *args));
}

#endif

const ModuleEntry ssl_entries[] = {
        MODULE_EXPORT_TYPE(type_sslcontext_),
        MODULE_EXPORT_TYPE(type_sslsocket_),

#ifdef _ARGON_PLATFORM_WINDOWS
        MODULE_EXPORT_FUNCTION(ssl_enumcerts),
#endif

        ARGON_MODULE_SENTINEL
};

bool SSLInit(Module *self) {
#define AddIntConstant(name, value)                 \
    if(!ModuleAddIntConstant(self, #name, value))   \
        return false

    AddIntConstant(CERT_NONE, (int) SSLVerify::CERT_NONE);
    AddIntConstant(CERT_OPTIONAL, (int) SSLVerify::CERT_OPTIONAL);
    AddIntConstant(CERT_REQUIRED, (int) SSLVerify::CERT_REQUIRED);

    AddIntConstant(PROTO_TLS, (int) SSLProtocol::TLS);
    AddIntConstant(PROTO_TLS_CLIENT, (int) SSLProtocol::TLS_CLIENT);
    AddIntConstant(PROTO_TLS_SERVER, (int) SSLProtocol::TLS_SERVER);

    AddIntConstant(VERSION_SSL3, SSL3_VERSION);
    AddIntConstant(VERSION_TLS1, TLS1_VERSION);
    AddIntConstant(VERSION_TLS11, TLS1_1_VERSION);
    AddIntConstant(VERSION_TLS12, TLS1_2_VERSION);
    AddIntConstant(VERSION_TLS13, TLS1_3_VERSION);

    AddIntConstant(FILETYPE_ASN1, SSL_FILETYPE_ASN1);
    AddIntConstant(FILETYPE_PEM, SSL_FILETYPE_PEM);

    AddIntConstant(AD_REASON_OFFSET, SSL_AD_REASON_OFFSET);
    AddIntConstant(AD_CLOSE_NOTIFY, SSL_AD_CLOSE_NOTIFY);
    AddIntConstant(AD_UNEXPECTED_MESSAGE, SSL_AD_UNEXPECTED_MESSAGE);
    AddIntConstant(AD_BAD_RECORD_MAC, SSL_AD_BAD_RECORD_MAC);
    AddIntConstant(AD_DECRYPTION_FAILED, SSL_AD_DECRYPTION_FAILED);
    AddIntConstant(AD_RECORD_OVERFLOW, SSL_AD_RECORD_OVERFLOW);
    AddIntConstant(AD_DECOMPRESSION_FAILURE, SSL_AD_DECOMPRESSION_FAILURE);
    AddIntConstant(AD_HANDSHAKE_FAILURE, SSL_AD_HANDSHAKE_FAILURE);
    AddIntConstant(AD_NO_CERTIFICATE, SSL_AD_NO_CERTIFICATE);
    AddIntConstant(AD_BAD_CERTIFICATE, SSL_AD_BAD_CERTIFICATE);
    AddIntConstant(AD_UNSUPPORTED_CERTIFICATE, SSL_AD_UNSUPPORTED_CERTIFICATE);
    AddIntConstant(AD_CERTIFICATE_REVOKED, SSL_AD_CERTIFICATE_REVOKED);
    AddIntConstant(AD_CERTIFICATE_EXPIRED, SSL_AD_CERTIFICATE_EXPIRED);
    AddIntConstant(AD_CERTIFICATE_UNKNOWN, SSL_AD_CERTIFICATE_UNKNOWN);
    AddIntConstant(AD_ILLEGAL_PARAMETER, SSL_AD_ILLEGAL_PARAMETER);
    AddIntConstant(AD_UNKNOWN_CA, SSL_AD_UNKNOWN_CA);
    AddIntConstant(AD_ACCESS_DENIED, SSL_AD_ACCESS_DENIED);
    AddIntConstant(AD_DECODE_ERROR, SSL_AD_DECODE_ERROR);
    AddIntConstant(AD_DECRYPT_ERROR, SSL_AD_DECRYPT_ERROR);
    AddIntConstant(AD_EXPORT_RESTRICTION, SSL_AD_EXPORT_RESTRICTION);
    AddIntConstant(AD_PROTOCOL_VERSION, SSL_AD_PROTOCOL_VERSION);
    AddIntConstant(AD_INSUFFICIENT_SECURITY, SSL_AD_INSUFFICIENT_SECURITY);
    AddIntConstant(AD_INTERNAL_ERROR, SSL_AD_INTERNAL_ERROR);
    AddIntConstant(AD_USER_CANCELLED, SSL_AD_USER_CANCELLED);
    AddIntConstant(AD_NO_RENEGOTIATION, SSL_AD_NO_RENEGOTIATION);
    AddIntConstant(AD_UNSUPPORTED_EXTENSION, SSL_AD_UNSUPPORTED_EXTENSION);
    AddIntConstant(AD_CERTIFICATE_UNOBTAINABLE, SSL_AD_CERTIFICATE_UNOBTAINABLE);
    AddIntConstant(AD_UNRECOGNIZED_NAME, SSL_AD_UNRECOGNIZED_NAME);
    AddIntConstant(AD_BAD_CERTIFICATE_STATUS_RESPONSE, SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE);
    AddIntConstant(AD_BAD_CERTIFICATE_HASH_VALUE, SSL_AD_BAD_CERTIFICATE_HASH_VALUE);
    AddIntConstant(AD_UNKNOWN_PSK_IDENTITY, SSL_AD_UNKNOWN_PSK_IDENTITY);


    if (!TypeInit((TypeInfo *) arlib::ssl::type_sslcontext_, nullptr))
        return false;

    if (!TypeInit((TypeInfo *) arlib::ssl::type_sslsocket_, nullptr))
        return false;

    return true;
#undef AddIntConstant
}

bool SSLFini([[maybe_unused]]Module *self) {
    return true;
}

constexpr ModuleInit ModuleSSL = {
        "ssl",
        "This module provides access to SSL/TLS encryption and peer authentication facilities "
        "for network sockets (client & server side).",
        ARLIB_VERSION,
        ssl_entries,
        SSLInit,
        SSLFini
};

ARGON_MODULE_INIT(ModuleSSL)

static ArObject *ASN1Obj2Ar(const ASN1_OBJECT *name) {
    static constexpr int kX509_NAME_MAXLEN = 256;

    char buf[kX509_NAME_MAXLEN];
    char *namebuf = buf;
    String *aname;

    int buflen;

    if ((buflen = OBJ_obj2txt(namebuf, kX509_NAME_MAXLEN, name, 0)) < 0) {
        SSLError();

        return nullptr;
    }

    if (buflen > kX509_NAME_MAXLEN - 1) {
        buflen = OBJ_obj2txt(nullptr, 0, name, 0);

        if ((namebuf = (char *) argon::vm::memory::Alloc(buflen + 1)) == nullptr)
            return nullptr;

        if ((buflen = OBJ_obj2txt(namebuf, kX509_NAME_MAXLEN, name, 0)) < 0) {
            argon::vm::memory::Free(namebuf);

            SSLError();

            return nullptr;
        }
    }

    if (buf != namebuf) {
        if ((aname = StringNewHoldBuffer((unsigned char *) namebuf, buflen)) == nullptr) {
            argon::vm::memory::Free(namebuf);

            return nullptr;
        }
    } else
        aname = StringNew(namebuf, buflen);

    return (ArObject *) aname;
}

static ArObject *AiaURI(const X509 *cert, int nid) {
    AUTHORITY_INFO_ACCESS *info;
    String *tmp;
    List *list;
    Tuple *ret;

    info = (AUTHORITY_INFO_ACCESS *) X509_get_ext_d2i(cert, NID_info_access, nullptr, nullptr);
    if (info == nullptr)
        return ARGON_NIL_VALUE;

    if (sk_ACCESS_DESCRIPTION_num(info) == 0) {
        AUTHORITY_INFO_ACCESS_free(info);
        return ARGON_NIL_VALUE;
    }

    if ((list = ListNew()) == nullptr) {
        AUTHORITY_INFO_ACCESS_free(info);
        return nullptr;
    }

    for (int i = 0; i < sk_ACCESS_DESCRIPTION_num(info); i++) {
        const ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(info, i);
        const ASN1_IA5STRING *uri;

        if ((OBJ_obj2nid(ad->method) != nid) || (ad->location->type != GEN_URI))
            continue;

        uri = ad->location->d.uniformResourceIdentifier;

        if ((tmp = StringNew((const char *) uri->data, uri->length)) == nullptr) {
            AUTHORITY_INFO_ACCESS_free(info);

            Release(list);

            return nullptr;
        }

        if (!ListAppend(list, (ArObject *) tmp)) {
            AUTHORITY_INFO_ACCESS_free(info);

            Release(list);

            return nullptr;
        }

        Release(tmp);
    }

    AUTHORITY_INFO_ACCESS_free(info);

    ret = TupleConvertList(&list);

    Release(list);

    return (ArObject *) ret;
}

static ArObject *DistributionPoints(const X509 *cert) {
    STACK_OF(DIST_POINT) *dps;
    List *list;
    Tuple *ret;

    dps = (STACK_OF(DIST_POINT) *) X509_get_ext_d2i(cert, NID_crl_distribution_points, nullptr, nullptr);

    if (dps == nullptr)
        return ARGON_NIL_VALUE;

    if ((list = ListNew()) == nullptr)
        return nullptr;

    for (int i = 0; i < sk_DIST_POINT_num(dps); i++) {
        DIST_POINT *dp;
        STACK_OF(GENERAL_NAME) *gns;

        dp = sk_DIST_POINT_value(dps, i);
        if (dp->distpoint == nullptr)
            continue;

        gns = dp->distpoint->name.fullname;

        for (int j = 0; j < sk_GENERAL_NAME_num(gns); j++) {
            const GENERAL_NAME *gn;
            const ASN1_IA5STRING *uri;
            String *tmp;

            gn = sk_GENERAL_NAME_value(gns, j);
            if (gn->type != GEN_URI)
                continue;

            uri = gn->d.uniformResourceIdentifier;
            if ((tmp = StringNew((const char *) uri->data, uri->length)) == nullptr) {
                CRL_DIST_POINTS_free(dps);

                Release(list);

                return nullptr;
            }

            if (!ListAppend(list, (ArObject *) tmp)) {
                CRL_DIST_POINTS_free(dps);

                Release(list);
                Release(tmp);

                return nullptr;
            }

            Release(tmp);
        }
    }

    ret = TupleConvertList(&list);

    Release(list);

    return (ArObject *) ret;
}

static ArObject *SubjectAltName(const X509 *cert) {
    char buf[2048];

    List *alt_names = nullptr;
    GENERAL_NAMES *names;
    BIO *biobuf;

    Tuple *ret;

    if (cert == nullptr)
        return ARGON_NIL_VALUE;

    if ((biobuf = BIO_new(BIO_s_mem())) == nullptr) {
        argon::vm::Panic((ArObject *) error_oom);

        return nullptr;
    }

    names = (GENERAL_NAMES *) X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr);
    if (names != nullptr) {
        Tuple *tuple_tmp = nullptr;

        if ((alt_names = ListNew()) == nullptr) {
            BIO_free(biobuf);
            return nullptr;
        }

        for (int i = 0; i < sk_GENERAL_NAME_num(names); i++) {
            const ASN1_STRING *as;
            GENERAL_NAME *name;

            ArObject *tmp;
            String *str_tmp;
            String *str_tmp1;

            const char *vptr;
            int len;

            tuple_tmp = nullptr;

            name = sk_GENERAL_NAME_value(names, i);

            if (name->type == GEN_DIRNAME) {
                if ((tmp = (ArObject *) TupleX509Name(name->d.dirn)) == nullptr)
                    break;

                tuple_tmp = TupleNew("so", "DirName", tmp);

                Release(tmp);
            } else if (name->type == GEN_EMAIL) {
                as = name->d.rfc822Name;
                if ((str_tmp = StringNew((const char *) ASN1_STRING_get0_data(as), ASN1_STRING_length(as))) == nullptr)
                    break;

                tuple_tmp = TupleNew("so", "email", str_tmp);

                Release(str_tmp);
            } else if (name->type == GEN_DNS) {
                as = name->d.dNSName;
                if ((str_tmp = StringNew((const char *) ASN1_STRING_get0_data(as), ASN1_STRING_length(as))) == nullptr)
                    break;

                tuple_tmp = TupleNew("so", "DNS", str_tmp);

                Release(str_tmp);
            } else if (name->type == GEN_URI) {
                as = name->d.uniformResourceIdentifier;
                if ((str_tmp = StringNew((const char *) ASN1_STRING_get0_data(as), ASN1_STRING_length(as))) == nullptr)
                    break;

                tuple_tmp = TupleNew("so", "URI", str_tmp);

                Release(str_tmp);
            } else if (name->type == GEN_RID) {
                if ((len = i2t_ASN1_OBJECT(buf, sizeof(buf) - 1, name->d.rid)) < 0) {
                    SSLError();

                    break;
                }

                if (len >= sizeof(buf))
                    str_tmp = StringNew("<INVALID>");
                else
                    str_tmp = StringNew(buf, len);

                if (str_tmp == nullptr)
                    break;

                tuple_tmp = TupleNew("so", "Registered ID", str_tmp);

                Release(str_tmp);
            } else if (name->type == GEN_IPADD) {
                const unsigned char *ip = name->d.ip->data;

                if (name->d.ip->length == 4)
                    str_tmp = StringFormat("%d.%d.%d.%d",
                                           ip[0], ip[1], ip[2], ip[3]);
                else if (name->d.ip->length == 6)
                    str_tmp = StringFormat("%X:%X:%X:%X:%X:%X:%X:%X",
                                           ip[0] << 8u | ip[1],
                                           ip[2] << 8u | ip[3],
                                           ip[4] << 8u | ip[5],
                                           ip[6] << 8u | ip[7],
                                           ip[8] << 8u | ip[9],
                                           ip[10] << 8u | ip[11],
                                           ip[12] << 8u | ip[13],
                                           ip[14] << 8u | ip[15]);
                else
                    str_tmp = StringNew("<INVALID>");

                tuple_tmp = TupleNew("so", "IP Address", str_tmp);

                Release(str_tmp);
            } else {
                if (name->type != GEN_OTHERNAME &&
                    name->type != GEN_X400 &&
                    name->type != GEN_EDIPARTY &&
                    name->type != GEN_RID) {
                    ErrorFormat(kSSLError[0], "unknown general name type %d", name->type);

                    break;
                }

                BIO_reset(biobuf);

                GENERAL_NAME_print(biobuf, name);

                if ((len = BIO_gets(biobuf, buf, sizeof(buf) - 1)) < 0) {
                    SSLError();

                    break;
                }

                if ((vptr = strchr(buf, ':')) == nullptr) {
                    ErrorFormat(kValueError[0], "invalid value %.200s", buf);
                    break;
                }

                if ((str_tmp = StringNew(buf, (vptr - buf))) == nullptr)
                    break;

                if ((str_tmp1 = StringNew((vptr + 1), len - (vptr - buf + 1))) == nullptr) {
                    Release(str_tmp);

                    break;
                }

                tuple_tmp = TupleNew("oo", str_tmp, str_tmp1);

                Release(str_tmp);
                Release(str_tmp1);
            }

            if (tuple_tmp == nullptr)
                break;

            if (!ListAppend(alt_names, (ArObject *) tuple_tmp)) {
                Release(tuple_tmp);

                break;
            }

            Release(tuple_tmp);
        }

        sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);

        if (tuple_tmp == nullptr) {
            BIO_free(biobuf);

            Release(alt_names);

            return nullptr;
        }
    }

    BIO_free(biobuf);

    if (alt_names != nullptr) {
        ret = TupleNew((ArObject *) alt_names);
        Release(alt_names);

        return (ArObject *) ret;
    }

    return ARGON_NIL_VALUE;
}

Bytes *arlib::ssl::CertToDer(X509 *cert) {
    Bytes *ret;
    unsigned char *buf;
    int len;

    if ((len = i2d_X509(cert, &buf)) < 0) {
        SSLError();

        return nullptr;
    }

    ret = BytesNew(buf, len, true);

    OPENSSL_free(buf);

    return ret;
}

Dict *arlib::ssl::DecodeCert(X509 *cert) {
    char buf[2048];

    ArObject *tmp;
    String *str_tmp;
    Dict *ret;
    BIO *biobuf;

    int len;

    if ((ret = DictNew()) == nullptr)
        return nullptr;

    // PEER

    if ((tmp = (ArObject *) TupleX509Name(X509_get_subject_name(cert))) == nullptr) {
        Release(ret);
        return nullptr;
    }

    if (!DictInsert(ret, "subject", tmp))
        goto ERROR;

    Release(&tmp);

    // ISSUER

    if ((tmp = (ArObject *) TupleX509Name(X509_get_issuer_name(cert))) == nullptr) {
        Release(ret);
        return nullptr;
    }

    if (!DictInsert(ret, "issuer", tmp))
        goto ERROR;

    Release(&tmp);

    // VERSION

    if ((tmp = (ArObject *) IntNew(X509_get_version(cert) + 1)) == nullptr)
        goto ERROR;

    if (!DictInsert(ret, "version", tmp))
        goto ERROR;

    Release(&tmp);

    if ((biobuf = BIO_new(BIO_s_mem())) == nullptr)
        goto ERROR;

    // SERIAL NUMBER

    BIO_reset(biobuf);
    i2a_ASN1_INTEGER(biobuf, X509_get_serialNumber(cert));
    if ((len = BIO_gets(biobuf, buf, sizeof(buf) - 1)) < 0) {
        SSLError();

        goto ERROR;
    }

    if ((str_tmp = StringNew(buf, len)) == nullptr)
        goto ERROR;

    if (!DictInsert(ret, "serialNumber", (ArObject *) str_tmp))
        goto ERROR;

    Release((ArObject **) &str_tmp);

    // NOT BEFORE

    BIO_reset(biobuf);
    ASN1_TIME_print(biobuf, X509_get0_notBefore(cert));
    if ((len = BIO_gets(biobuf, buf, sizeof(buf) - 1)) < 0) {
        SSLError();

        goto ERROR;
    }

    if ((str_tmp = StringNew(buf, len)) == nullptr)
        goto ERROR;

    if (!DictInsert(ret, "notBefore", (ArObject *) str_tmp))
        goto ERROR;

    Release((ArObject **) &str_tmp);

    // NOT AFTER

    BIO_reset(biobuf);
    ASN1_TIME_print(biobuf, X509_get0_notAfter(cert));
    if ((len = BIO_gets(biobuf, buf, sizeof(buf) - 1)) < 0) {
        SSLError();

        goto ERROR;
    }

    if ((str_tmp = StringNew(buf, len)) == nullptr)
        goto ERROR;

    if (!DictInsert(ret, "notAfter", (ArObject *) str_tmp))
        goto ERROR;

    Release((ArObject **) &str_tmp);

    BIO_free(biobuf);

    if ((tmp = SubjectAltName(cert)) == nullptr)
        goto ERROR;

    if (!DictInsert(ret, "subjectAltName", tmp))
        goto ERROR;

    Release(&tmp);

    if ((tmp = AiaURI(cert, NID_ad_OCSP)) == nullptr)
        goto ERROR;

    if (!DictInsert(ret, "OCSP", tmp))
        goto ERROR;

    Release(&tmp);

    if ((tmp = AiaURI(cert, NID_ad_ca_issuers)) == nullptr)
        goto ERROR;

    if (!DictInsert(ret, "caIssuers", tmp))
        goto ERROR;

    Release(&tmp);

    if ((tmp = DistributionPoints(cert)) == nullptr)
        goto ERROR;

    if (!DictInsert(ret, "crlDistributionPoints", tmp))
        goto ERROR;

    Release(tmp);

    return ret;

    ERROR:
    Release(tmp);
    Release(ret);

    return nullptr;
}

static Tuple *Attribute2Tuple(const ASN1_OBJECT *name, const ASN1_STRING *value) {
    ArObject *asn1obj = ASN1Obj2Ar(name);
    String *tmp;
    Tuple *retval;

    ArSSize buflen;

    if (asn1obj == nullptr)
        return nullptr;

    if (ASN1_STRING_type(value) == V_ASN1_BIT_STRING) {
        buflen = ASN1_STRING_length(value);

        if ((tmp = StringNew((const char *) ASN1_STRING_get0_data(value), buflen)) == nullptr) {
            Release(asn1obj);
            return nullptr;
        }
    } else {
        unsigned char *buf;

        if ((buflen = ASN1_STRING_to_UTF8(&buf, value)) < 0) {
            SSLError();

            Release(asn1obj);

            return nullptr;
        }

        if ((tmp = StringNew((const char *) buf, buflen)) == nullptr) {
            Release(asn1obj);

            return nullptr;
        }

        OPENSSL_free(buf);
    }

    retval = TupleNew("oo", asn1obj, tmp);
    Release(asn1obj);

    return retval;
}

static Tuple *TupleX509Name(const X509_NAME *name) {
    const X509_NAME_ENTRY *entry;
    const ASN1_OBJECT *as_name;
    const ASN1_STRING *value;

    ArObject *ret;
    ArObject *tmp;
    List *dn;
    List *rdn;

    int entry_count = X509_NAME_entry_count(name);
    int rdn_level = -1;

    if ((dn = ListNew()) == nullptr)
        return nullptr;

    if ((rdn = ListNew()) == nullptr) {
        Release(dn);
        return nullptr;
    }

    for (int i = 0; i < entry_count; i++) {
        entry = X509_NAME_get_entry(name, i);

        if (rdn_level >= 0 && rdn_level != X509_NAME_ENTRY_set(entry)) {
            if ((ret = (ArObject *) TupleNew((ArObject *) rdn)) == nullptr) {
                Release(dn);
                Release(rdn);

                return nullptr;
            }

            Release(rdn);

            if (!ListAppend(dn, ret)) {
                Release(dn);
                Release(ret);

                return nullptr;
            }

            Release(&ret);

            if ((rdn = ListNew()) == nullptr) {
                Release(dn);

                return nullptr;
            }
        }

        rdn_level = X509_NAME_ENTRY_set(entry);

        as_name = X509_NAME_ENTRY_get_object(entry);
        value = X509_NAME_ENTRY_get_data(entry);

        if ((tmp = (ArObject *) Attribute2Tuple(as_name, value)) == nullptr) {
            Release(dn);
            Release(rdn);

            return nullptr;
        }

        if (!ListAppend(rdn, tmp)) {
            Release(dn);
            Release(rdn);
            Release(tmp);

            return nullptr;
        }

        Release(tmp);
    }

    if (rdn->length > 0) {
        if ((ret = (ArObject *) TupleNew((ArObject *) rdn)) == nullptr) {
            Release(dn);
            Release(rdn);

            return nullptr;
        }

        Release(rdn);

        if (!ListAppend(dn, ret)) {
            Release(dn);
            Release(ret);

            return nullptr;
        }

        Release(&ret);
    }

    Release(rdn);

    ret = (ArObject *) TupleNew((ArObject *) dn);
    Release(dn);

    return (Tuple *) ret;
}

Error *arlib::ssl::SSLErrorNew() {
    char buf[256] = {};
    Error *err;

    if (ERR_error_string(ERR_get_error(), buf) == nullptr)
        err = ErrorNew(kSSLError[0], "unknown error");
    else
        err = ErrorNew(kSSLError[0], buf);

    return err;
}

void arlib::ssl::SSLError() {
    Error *err = SSLErrorNew();

    if (err != nullptr) {
        argon::vm::Panic((ArObject *) err);
        Release(err);
    }
}
