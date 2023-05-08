// This source file is part of the Argon project.
//
// Licensed under the Apache License v2.0

#include <argon/util/macros.h>

#ifdef _ARGON_PLATFORM_WINDOWS

#include <argon/vm/datatype/boolean.h>
#include <argon/vm/datatype/bytes.h>
#include <argon/vm/datatype/error.h>
#include <argon/vm/datatype/integer.h>
#include <argon/vm/datatype/set.h>

#include <ssl/ssl.h>

using namespace argon::vm::datatype;
using namespace arlib::ssl;

static HCERTSTORE CollectCertificates(const char *name) {
    static constexpr std::array<DWORD, 7> system_stores = {
            CERT_SYSTEM_STORE_LOCAL_MACHINE,
            CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE,
            CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY,
            CERT_SYSTEM_STORE_CURRENT_USER,
            CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY,
            CERT_SYSTEM_STORE_SERVICES,
            CERT_SYSTEM_STORE_USERS};

    HCERTSTORE my_store;
    HCERTSTORE sys_store;

    ArSize count = 0;

    if ((my_store = CertOpenStore(CERT_STORE_PROV_COLLECTION, 0, (HCRYPTPROV) nullptr, 0, nullptr)) == nullptr)
        return nullptr;

    for (auto cursor: system_stores) {
        sys_store = CertOpenStore(CERT_STORE_PROV_SYSTEM_A,
                                  0,
                                  (HCRYPTPROV) nullptr,
                                  CERT_STORE_READONLY_FLAG | cursor,
                                  name);

        if (sys_store != nullptr) {
            if (CertAddStoreToCollection(my_store, sys_store, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 0))
                count++;

            CertCloseStore(sys_store, 0);
        }
    }

    if (count == 0) {
        CertCloseStore(my_store, 0);
        return nullptr;
    }

    return my_store;
}

static ArObject *EncodingTypes(DWORD encoding) {
    switch (encoding) {
        case X509_ASN_ENCODING:
            return (ArObject *) StringIntern("x509_asn");
        case PKCS_7_ASN_ENCODING:
            return (ArObject *) StringIntern("pkcs_7_asn");
        default:
            return (ArObject *) IntNew((IntegerUnderlying) encoding);
    }
}

static ArObject *KeyUsage(PCCERT_CONTEXT cert, DWORD flags) {
    CERT_ENHKEY_USAGE *usage;
    ArObject *ret;
    String *tmp;

    DWORD size;
    DWORD error;

    if (CertGetEnhancedKeyUsage(cert, flags, nullptr, &size) == 0) {
        error = GetLastError();
        if (error == CRYPT_E_NOT_FOUND)
            return BoolToArBool(true);

        ErrorFromWinErr();
        return nullptr;
    }

    if ((usage = (CERT_ENHKEY_USAGE *) argon::vm::memory::Alloc(size)) == nullptr)
        return nullptr;

    if (CertGetEnhancedKeyUsage(cert, flags, usage, &size) == 0) {
        argon::vm::memory::Free(usage);

        error = GetLastError();
        if (error == CRYPT_E_NOT_FOUND)
            return BoolToArBool(true);

        ErrorFromWinErr();

        return nullptr;
    }

    if ((ret = (ArObject *) SetNew()) == nullptr) {
        argon::vm::memory::Free(usage);

        return nullptr;
    }

    for (int i = 0; i < usage->cUsageIdentifier; ++i) {
        if (usage->rgpszUsageIdentifier[i]) {
            if ((tmp = StringNew(usage->rgpszUsageIdentifier[i])) == nullptr) {
                argon::vm::memory::Free(usage);

                Release(ret);

                return nullptr;
            }

            if (!SetAdd((Set *) ret, (ArObject *) tmp)) {
                argon::vm::memory::Free(usage);

                Release(tmp);
                Release(ret);

                return nullptr;
            }

            Release(tmp);
        }
    }

    argon::vm::memory::Free(usage);

    return ret;
}

Tuple *arlib::ssl::EnumWindowsCert(const char *store_name) {
    PCCERT_CONTEXT pcert = nullptr;
    HCERTSTORE my_store;
    ArObject *cert = nullptr;
    ArObject *encoding = nullptr;
    ArObject *keyusage = nullptr;
    Tuple *tuple = nullptr;
    Set *set;

    if ((set = SetNew()) == nullptr)
        return nullptr;

    if ((my_store = CollectCertificates(store_name)) == nullptr) {
        Release(set);

        ErrorFromWinErr();

        return nullptr;
    }

    while ((pcert = CertEnumCertificatesInStore(my_store, pcert))) {
        if ((cert = (ArObject *) BytesNew(pcert->pbCertEncoded, pcert->cbCertEncoded, true)) == nullptr)
            break;

        if ((encoding = EncodingTypes(pcert->dwCertEncodingType)) == nullptr)
            break;

        if ((keyusage = KeyUsage(pcert, CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG)) == (ArObject *) True)
            keyusage = KeyUsage(pcert, CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG);

        if (keyusage == nullptr)
            break;

        tuple = TupleNew("ooo", cert, encoding, keyusage);

        Release(&cert);
        Release(&encoding);
        Release(&keyusage);

        if (tuple == nullptr)
            break;

        if (!SetAdd(set, (ArObject *) tuple)) {
            Release((ArObject **) &tuple);

            break;
        }

        Release((ArObject **) &tuple);
    }

    if (pcert != nullptr)
        CertFreeCertificateContext(pcert);

    Release(cert);
    Release(encoding);
    Release(keyusage);
    Release(tuple);

    if (!CertCloseStore(my_store, CERT_CLOSE_STORE_FORCE_FLAG)) {
        Release(set);

        ErrorFromWinErr();
        return nullptr;
    }

    tuple = TupleNew((ArObject *) set);

    Release(set);

    return tuple;
}

#endif