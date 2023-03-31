#pragma once
#define _NTDEF_ // Required to include both Ntsecapi and Winternl
#include <Winternl.h>

#include <Ntsecapi.h>
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

    typedef struct _QUERY_TKT_CACHE_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::QueryTicketCache };
        LUID LogonId;
    } QUERY_TKT_CACHE_REQUEST, *PQUERY_TKT_CACHE_REQUEST;

    class Proxy {
    public:
        Proxy(const std::shared_ptr<Lsa>& lsa);

        // A subset of the supported functions in Kerberos
        bool QueryTicketCache(PLUID luid) const;
        // bool KerbChangeMachinePassword(const std::wstring username, const std::wstring domain, CacheLookupCredType type, const std::string credential) const;

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