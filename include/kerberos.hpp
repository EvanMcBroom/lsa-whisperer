#pragma once
#include <pch.hpp>

#include <lsa.hpp>
#include <memory>
#include <netlogon.hpp>
#include <string>
#include <vector>

namespace Kerberos {
    enum class CacheOptions : ULONG {
        Default = 0x0,
        DontUseCache = 0x1,
        UseCacheOnly = 0x2,
        UseCredhandle = 0x4,
        // NT 5.1
        AsKerbCred = 0x8,
        WithSecCred = 0x10,
        // NT 6.0
        CACHE_TICKET = 0x20,
        // NT 6.1
        MAX_LIFETIME = 0x40
    };

    enum class EncryptionType {
        Null = 0,
        DesCbcCrc = 1,
        DesCbcMd4 = 2,
        DesCbcMd5 = 3,
        Aes128CtsHmacSha1_96 = 17,
        Aes256CtsHmacSha1_96 = 18,
        Rc4Md4 = -128,
        Rc4Plain2 = -129,
        Rc4Lm = -130,
        Rc4sha = -131,
        DesPlan = -132,
        Rc4HmacOld = -133,
        Rc4PlainOld = -134,
        Rc4HmacOldExp = -135,
        Rc4PlainOldExp = -136,
        Rc4Plain = -140,
        Rc4PlainExp = -141
    };

    enum class PROTOCOL_MESSAGE_TYPE : ULONG {
        DebugRequest = 0,
        QueryTicketCache,
        ChangeMachinePassword,
        VerifyPac,
        RetrieveTicket,
        UpdateAddresses,
        PurgeTicketCache,
        ChangePassword,
        RetrieveEncodedTicket,
        DecryptData,
        AddBindingCacheEntry,
        SetPassword,
        SetPasswordEx,
        VerifyCredentials,
        QueryTicketCacheEx,
        PurgeTicketCacheEx,
        RefreshSmartcardCredentials,
        AddExtraCredentials,
        QuerySupplementalCredentials,
        TransferCredentials,
        QueryTicketCacheEx2,
        SubmitTicket,
        AddExtraCredentialsEx,
        QueryKdcProxyCache,
        PurgeKdcProxyCache,
        QueryTicketCacheEx3,
        CleanupMachinePkinitCreds,
        AddBindingCacheEntryEx,
        QueryBindingCache,
        PurgeBindingCache,
        PinKdc,
        UnpinAllKdcs,
        QueryDomainExtendedPolicies,
        QueryS4U2ProxyCache,
        RetrieveKeyTab,
        RefreshPolicy,
        PrintCloudKerberosDebug
    };

    enum class TicketFlags : ULONG {
        Reserved1 = 0x00000001,
        NameCanonicalize = 0x00010000,
        EncPaRep = 0x00010000,
        CNameInPaData = 0x00040000, // Only valid on NT 5.1
        OkAsDelegate = 0x00040000,
        HwAuthent = 0x00100000,
        PreAuthent = 0x00200000,
        Initial = 0x00400000,
        Renewable = 0x00800000,
        Invalid = 0x01000000,
        PostDated = 0x02000000,
        MayPostdate = 0x04000000,
        Proxy = 0x08000000,
        Proxiable = 0x10000000,
        Forwarded = 0x20000000,
        Forwardable = 0x40000000,
        Feserved = 0x80000000
    };

    /*
                required structure for call KerbChangeMachinePasswordMessage

    */
    typedef struct _CHANGE_MACH_PWD_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::ChangeMachinePassword };
        UNICODE_STRING NewPassword;
        UNICODE_STRING OldPassword;
    } CHANGE_MACH_PWD_REQUEST, * PCHANGE_MACH_PWD_REQUEST;


    typedef struct _RETRIEVE_TKT_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::RetrieveEncodedTicket };
        LUID LogonId;
        UNICODE_STRING TargetName;
        ULONG TicketFlags;
        ULONG CacheOptions;
        LONG EncryptionType;
        SecHandle CredentialsHandle{ 0 };
    } RETRIEVE_TKT_REQUEST, *PRETRIEVE_TKT_REQUEST;

    typedef struct _RETRIEVE_TKT_RESPONSE {
        KERB_EXTERNAL_TICKET Ticket;
    } RETRIEVE_TKT_RESPONSE, *PRETRIEVE_TKT_RESPONSE;
  
    typedef struct _PIN_KDC : _SECPKG_CALL_PACKAGE_PIN_DC_REQUEST {
        _PIN_KDC() {
            MessageType = static_cast<ULONG>(PROTOCOL_MESSAGE_TYPE::PinKdc);
        }
    } PIN_KDC, *PPIN_KDC;

    typedef struct _PURGE_TKT_CACHE_REQUEST : KERB_PURGE_TKT_CACHE_REQUEST {
        _PURGE_TKT_CACHE_REQUEST() {
            MessageType = static_cast<KERB_PROTOCOL_MESSAGE_TYPE>(PROTOCOL_MESSAGE_TYPE::PurgeTicketCache);
        }
    } PURGE_TKT_CACHE_REQUEST, *PPURGE_TKT_CACHE_REQUEST;

    typedef struct _PURGE_TKT_CACHE_EX_REQUEST : KERB_PURGE_TKT_CACHE_EX_REQUEST {
        _PURGE_TKT_CACHE_EX_REQUEST() {
            MessageType = static_cast<KERB_PROTOCOL_MESSAGE_TYPE>(PROTOCOL_MESSAGE_TYPE::PurgeTicketCacheEx);
        }
    } PURGE_TKT_CACHE_EX_REQUEST, *PPURGE_TKT_CACHE_EX_REQUEST;

    typedef struct _QUERY_TKT_CACHE_REQUEST : KERB_QUERY_TKT_CACHE_REQUEST {
        _QUERY_TKT_CACHE_REQUEST() {
            MessageType = static_cast<KERB_PROTOCOL_MESSAGE_TYPE>(PROTOCOL_MESSAGE_TYPE::QueryTicketCache);
        }
    } QUERY_TKT_CACHE_REQUEST, *PQUERY_TKT_CACHE_REQUEST;

    typedef struct _SECPKG_CALL_PACKAGE_UNPIN_ALL_DCS_REQUEST {
        ULONG MessageType;
        ULONG Flags; // reserved, must be 0
    } SECPKG_CALL_PACKAGE_UNPIN_ALL_DCS_REQUEST, *PSECPKG_CALL_PACKAGE_UNPIN_ALL_DCS_REQUEST;

    // TRANSFER_CRED_REQUEST::Flags may be CleanupCredentials or OptimisticLogon
    typedef struct _TRANSFER_CRED_REQUEST : _SECPKG_CALL_PACKAGE_TRANSFER_CRED_REQUEST {
        _TRANSFER_CRED_REQUEST() {
            MessageType = static_cast<ULONG>(PROTOCOL_MESSAGE_TYPE::TransferCredentials);
        }
    } TRANSFER_CRED_REQUEST, *PTRANSFER_CRED_REQUEST;

    typedef struct _UNPIN_ALL_KDCS : _SECPKG_CALL_PACKAGE_UNPIN_ALL_DCS_REQUEST {
        _UNPIN_ALL_KDCS() {
            MessageType = static_cast<ULONG>(PROTOCOL_MESSAGE_TYPE::UnpinAllKdcs);
        }
    } UNPIN_ALL_KDCS, *PUNPIN_ALL_KDCS;

    class Proxy {
    public:
        Proxy(const std::shared_ptr<Lsa>& lsa);

        // A subset of the supported functions in Kerberos
        bool QueryTicketCache(PLUID luid) const;
        bool ChangeMachinePassword(const std::wstring& oldPassword, const std::wstring& newPassword) const;
        bool RetrieveEncodedTicket(PLUID luid, const std::wstring& targetName, TicketFlags flags, CacheOptions options, EncryptionType type) const;
        bool TransferCreds(PLUID sourceLuid, PLUID destinationLuid, ULONG flags) const;

    protected:
        std::shared_ptr<Lsa> lsa;

    private:
        // You must free all returnBuffer outputs with LsaFreeReturnBuffer
        bool CallPackage(const std::string& submitBuffer, void** returnBuffer) const;

        template<typename _Request, typename _Response>
        bool CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const;

        template<typename _Request, typename _Response>
        bool CallPackage(_Request* submitBuffer, size_t submitBufferLength, _Response** returnBuffer) const;
    };
}