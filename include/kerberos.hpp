#pragma once
#include <pch.hpp>

#include <lsa.hpp>
#include <memory>
#include <netlogon.hpp>
#include <string>
#include <vector>

namespace Kerberos {
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
        AddExtraCredentialsMessage = 17,
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
        PrintCloudKerberosDebugMessage
    };

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