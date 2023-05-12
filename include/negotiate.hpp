#pragma once
#include <pch.hpp>

#include <lsa.hpp>

namespace Negotiate {
    constexpr auto MaxPrefix() {
        return 32;
    }

    enum class PROTOCOL_MESSAGE_TYPE : ULONG {
        EnumPackagePrefixes,
        GetCallerName,
        TransferCred,
        EnumPackageNames
    };

    typedef struct _CALLER_NAME_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::GetCallerName };
        LUID LogonId;
    } CALLER_NAME_REQUEST, *PCALLER_NAME_REQUEST;

    typedef struct _CALLER_NAME_RESPONSE {
        PROTOCOL_MESSAGE_TYPE MessageType;
        PWSTR CallerName;
    } CALLER_NAME_RESPONSE, *PCALLER_NAME_RESPONSE;

    typedef struct _PACKAGE_NAMES {
        ULONG NamesCount;
        UNICODE_STRING Names[1];
    } PACKAGE_NAMES, *PPACKAGE_NAMES;

    typedef struct _PACKAGE_PREFIX {
        ULONG_PTR PackageId;
        PVOID PackageDataA; // Unused, set to nullptr by negotiate
        PVOID PackageDataW; // Unused, set to nullptr by negotiate
        ULONG_PTR PrefixLen;
        UCHAR Prefix[MaxPrefix()];
    } PACKAGE_PREFIX, *PPACKAGE_PREFIX;

    typedef struct _PACKAGE_PREFIXES {
        ULONG MessageType;
        ULONG PrefixCount;
        ULONG Offset; // Offset to array of PACKAGE_PREFIX
        ULONG Pad;
    } PACKAGE_PREFIXES, *PPACKAGE_PREFIXES;

    // TRANSFER_CRED_REQUEST::Flags may be OptimisticLogon, CleanupCredentials, or ToSsoSession
    typedef struct _TRANSFER_CRED_REQUEST : _SECPKG_CALL_PACKAGE_TRANSFER_CRED_REQUEST {
        _TRANSFER_CRED_REQUEST() {
            MessageType = static_cast<ULONG>(PROTOCOL_MESSAGE_TYPE::TransferCred);
        }
    } TRANSFER_CRED_REQUEST, *PTRANSFER_CRED_REQUEST;

    class Proxy {
    public:
        Proxy(const std::shared_ptr<Lsa>& lsa);

        // A subset of the supported functions in negotiate
        bool EnumPackagePrefixes() const;
        bool GetCallerName(PLUID logonId) const;
        bool TransferCreds(PLUID sourceLuid, PLUID destinationLuid, ULONG flags) const;

    protected:
        std::shared_ptr<Lsa> lsa;

    private:
        // You must free all returnBuffer outputs with LsaFreeReturnBuffer
        template<typename _Request, typename _Response>
        bool CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const;
    };
}