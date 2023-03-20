#pragma once
#define _NTDEF_ // Required to include both Ntsecapi and Winternl
#include <Winternl.h>
#include <Ntsecapi.h>
#include <cxxopts.hpp>
#include <lsa.hpp>
#include <memory>
#include <netlogon.hpp>
#include <string>
#include <vector>


namespace Kerberos {
    enum class PROTOCOL_MESSAGE_TYPE : ULONG {
        KerbDebugRequestMessage = 0,
        KerbQueryTicketCacheMessage,
        KerbChangeMachinePasswordMessage,
        KerbVerifyPacMessage,
        KerbRetrieveTicketMessage,
        KerbUpdateAddressesMessage,
        KerbPurgeTicketCacheMessage,
        KerbChangePasswordMessage,
        KerbRetrieveEncodedTicketMessage,
        KerbDecryptDataMessage,
        KerbAddBindingCacheEntryMessage,
        KerbSetPasswordMessage,
        KerbSetPasswordExMessage,
#if (_WIN32_WINNT == 0x0500)
        KerbAddExtraCredentialsMessage = 17
#endif
#if (_WIN32_WINNT >= 0x0501)
        KerbVerifyCredentialsMessage,
        KerbQueryTicketCacheExMessage,
        KerbPurgeTicketCacheExMessage,
#endif
#if (_WIN32_WINNT >= 0x0502)
        KerbRefreshSmartcardCredentialsMessage,
        KerbAddExtraCredentialsMessage,
        KerbQuerySupplementalCredentialsMessage,
#endif
#if (_WIN32_WINNT >= 0x0600)
        KerbTransferCredentialsMessage,
        KerbQueryTicketCacheEx2Message,
        KerbSubmitTicketMessage,
        KerbAddExtraCredentialsExMessage,
#endif
#if (_WIN32_WINNT >= 0x0602)
        KerbQueryKdcProxyCacheMessage,
        KerbPurgeKdcProxyCacheMessage,
        KerbQueryTicketCacheEx3Message,
        KerbCleanupMachinePkinitCredsMessage,
        KerbAddBindingCacheEntryExMessage,
        KerbQueryBindingCacheMessage,
        KerbPurgeBindingCacheMessage,
        KerbPinKdcMessage,
        KerbUnpinAllKdcsMessage,
        KerbQueryDomainExtendedPoliciesMessage,
        KerbQueryS4U2ProxyCacheMessage,
#endif
#if (_WIN32_WINNT >= 0x0A00)
        KerbRetrieveKeyTabMessage,
        KerbRefreshPolicyMessage,
        KerbPrintCloudKerberosDebugMessage,
#endif
    };


    typedef struct _KERB_QUERY_TKT_CACHE_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::KerbQueryTicketCacheMessage };
        LUID LogonId;
    } KERB_QUERY_TKT_CACHE_REQUEST, *PKERB_QUERY_TKT_CACHE_REQUEST;


    class Proxy {
        public:
        Proxy(const std::shared_ptr<Lsa>& lsa);
            
        // A subset of the supported functions in Kerberos
        bool KerbQueryTicketCache(PLUID luid) const;
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
    bool HandleFunction(std::ostream& out, const Proxy& proxy, const std::string& function, const cxxopts::ParseResult& options);
    void Parse(std::ostream& out, const std::vector<std::string>& args);

}