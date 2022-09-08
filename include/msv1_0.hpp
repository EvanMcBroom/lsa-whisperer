#pragma once
#include <Windows.h>
#include <messages.hpp>
#include <string>

namespace {
    class UnicodeString : public UNICODE_STRING {
    public:
        UnicodeString(std::wstring data);
        ~UnicodeString();
    };

    bool CallPackage(const std::string& package, const std::string& submitBuffer, void** returnBuffer);
    PSID MakeDomainRelativeSid(PSID DomainId, ULONG RelativeId);
    void OutputHex(const std::string& data);
    void OutputHex(const std::string& prompt, const std::string& data);
}

namespace MSV1_0 {
    // You must free all returnBuffer outputs with LsaFreeReturnBuffer
    bool CallPackage(const std::string& submitBuffer, void** returnBuffer);
    template<typename _Request, typename _Response>
    bool CallPackage(const _Request& submitBuffer, _Response** returnBuffer);
    template<typename _Request, typename _Response>
    bool CallPackage(_Request* submitBuffer, size_t submitBufferLength, _Response** returnBuffer);

    // A subset of the supported functions in msv1_0
    bool CacheLogon(void* logonInfo, void* validationInfo, const std::vector<byte>& supplementalCacheData, ULONG flags);
    bool CacheLookupEx(const std::wstring username, const std::wstring domain, MSV1_0::CacheLookupCredType type, const std::string credential);
    bool ChangeCachedPassword(const std::wstring& domainName, const std::wstring& accountName, const std::wstring& oldPassword, const std::wstring& newPassword, bool impersonating);
    bool ClearCachedCredentials();
    bool DecryptDpapiMasterKey();
    bool DeleteTbalSecrets();
    bool DeriveCredential(PLUID luid, DeriveCredType type, const std::vector<byte>& mixingBits);
    bool EnumerateUsers(bool passthrough = false);
    bool GenericPassthrough(const std::wstring& domainName, const std::wstring& packageName, std::vector<byte>& data);
    bool GetCredentialKey(PLUID luid);
    bool GetStrongCredentialKey();
    bool GetUserInfo(PLUID luid);
    bool Lm20ChallengeRequest();
    bool ProvisionTbal(PLUID luid);
    bool SetProcessOption(ProcessOption options, bool disable);
    bool TransferCred(PLUID sourceLuid, PLUID destinationLuid);
}