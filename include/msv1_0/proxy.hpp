#pragma once
#include <lsa.hpp>
#include <memory>
#include <msv1_0/messages.hpp>
#include <string>

namespace Msv1_0 {
    class Proxy : public SspiProxy {
    public:
        // A subset of the supported functions in msv1_0
        bool CacheLogon(void* logonInfo, void* validationInfo, const std::vector<byte>& supplementalCacheData, ULONG flags) const;
        bool CacheLookupEx(const std::wstring username, const std::wstring domain, CacheLookupCredType type, const std::string credential) const;
        bool ChangeCachedPassword(const std::wstring& domainName, const std::wstring& accountName, const std::wstring& oldPassword, const std::wstring& newPassword, bool impersonating) const;
        bool ClearCachedCredentials() const;
        bool DecryptDpapiMasterKey() const;
        bool DeleteTbalSecrets() const;
        bool DeriveCredential(PLUID luid, DeriveCredType type, const std::vector<byte>& mixingBits) const;
        bool EnumerateUsers(bool passthrough = false) const;
        bool GenericPassthrough(const std::wstring& domainName, const std::wstring& packageName, std::vector<byte>& data) const;
        bool GetCredentialKey(PLUID luid) const;
        bool GetStrongCredentialKey() const;
        bool GetUserInfo(PLUID luid) const;
        bool Lm20ChallengeRequest() const;
        bool ProvisionTbal(PLUID luid) const;
        bool SetProcessOption(ProcessOption options, bool disable) const;
        bool TransferCred(PLUID sourceLuid, PLUID destinationLuid) const;

    private:
        // You must free all returnBuffer outputs with LsaFreeReturnBuffer
        bool CallPackage(const std::string& submitBuffer, void** returnBuffer) const;
        template<typename _Request, typename _Response>
        bool CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const;
        template<typename _Request, typename _Response>
        bool CallPackage(_Request* submitBuffer, size_t submitBufferLength, _Response** returnBuffer) const;
    };
}