// Copyright (C) 2025 Evan McBroom
#include "sspi/msv1_0.hpp"
#include "sspi/crypt.hpp"
#include <codecvt>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

namespace {
    // The Rtl* functions were dynamically resolved to save time during development
    PSID MakeDomainRelativeSid(PSID DomainId, ULONG RelativeId) {
        PSID result{ nullptr };
        auto library{ LoadLibraryW(L"ntdll.dll") };
        if (library) {
            using PRtlCopySid = NTSTATUS (*)(ULONG DestinationSidLength, PSID DestinationSid, PSID SourceSid);
            auto RtlCopySid{ reinterpret_cast<PRtlCopySid>(GetProcAddress(library, "RtlCopySid")) };
            using PRtlLengthRequiredSid = ULONG (*)(ULONG SubAuthorityCount);
            auto RtlLengthRequiredSid{ reinterpret_cast<PRtlLengthRequiredSid>(GetProcAddress(library, "RtlLengthRequiredSid")) };
            using PRtlSubAuthorityCountSid = PUCHAR (*)(PSID pSid);
            auto RtlSubAuthorityCountSid{ reinterpret_cast<PRtlSubAuthorityCountSid>(GetProcAddress(library, "RtlSubAuthorityCountSid")) };
            using PRtlSubAuthoritySid = LPDWORD (*)(PSID pSid, DWORD nSubAuthority);
            auto RtlSubAuthoritySid{ reinterpret_cast<PRtlSubAuthoritySid>(GetProcAddress(library, "RtlSubAuthoritySid")) };
            if (RtlCopySid && RtlLengthRequiredSid && RtlSubAuthorityCountSid && RtlSubAuthoritySid) {
                auto subAuthorityCount{ *(RtlSubAuthorityCountSid(DomainId)) }; // Should not fail
                auto length{ RtlLengthRequiredSid(subAuthorityCount + 1) }; // Should not fail
                auto sid{ reinterpret_cast<PSID>(std::malloc(length)) }; // Assume this succeeds for brevity
                if (SUCCEEDED(RtlCopySid(length, sid, DomainId))) {
                    (*(RtlSubAuthorityCountSid(sid)))++;
                    *RtlSubAuthoritySid(sid, subAuthorityCount) = RelativeId;
                    result = sid;
                }
            }
            FreeLibrary(library);
        }
        return result;
    }

    UNICODE_STRING WCharToUString(wchar_t* string) {
        if (string) {
            auto size{ lstrlenW(string) * sizeof(wchar_t) };
            return { (USHORT)size, (USHORT)((size) ? size + sizeof(wchar_t) : 0), (size) ? string : nullptr };
        }
        return { 0, 0, nullptr };
    }
}

namespace Msv1_0 {
    Api::Api(const std::shared_ptr<Lsa::Api>& lsa)
        : lsa(lsa) {
    }

    bool Api::CacheLogon(void* logonInfo, void* validationInfo, const std::vector<byte>& supplementalCacheData, ULONG flags) const {
        CACHE_LOGON_REQUEST request = { MsV1_0CacheLogon };
        request.LogonInformation = logonInfo;
        request.ValidationInformation = validationInfo;
        request.SupplementalCacheData = const_cast<byte*>(supplementalCacheData.data());
        request.SupplementalCacheDataLength = supplementalCacheData.size();
        void* response;
        return CallPackage(request, &response);
    }

    bool Api::CacheLookupEx(const std::wstring username, const std::wstring domain, ULONG type, const std::string credential) const {
        CACHE_LOOKUP_REQUEST request = { MsV1_0CacheLookupEx };
        UnicodeString userName{ username };
        request.UserName = userName;
        UnicodeString domainName{ domain };
        request.DomainName = domainName;
        request.CredentialType = type;
        request.CredentialInfoLength = credential.length();
        //&request.CredentialSubmitBuffer = credential.data();
        CACHE_LOOKUP_RESPONSE* response{ nullptr };
        // auto result{ CallPackage(request, credential.length() - 1, &response) };
        if (1) {
            // response.
        }
        return 1;
    }

    bool Api::ChangeCachedPassword(const std::wstring& domainName, const std::wstring& accountName, const std::wstring& newPassword) const {
        // Based off of schedsvc!NotifyLsaOfPasswordChange
        auto requestSize{ sizeof(MSV1_0_CHANGEPASSWORD_REQUEST) + ((domainName.length() + accountName.length() + newPassword.length() + 3) * sizeof(wchar_t)) };
        std::string requestBytes(requestSize, '\0');
        auto request{ reinterpret_cast<PMSV1_0_CHANGEPASSWORD_REQUEST>(requestBytes.data()) };
        request->MessageType = MsV1_0ChangeCachedPassword;

        auto ptrUstring{ reinterpret_cast<std::byte*>(request + 1) };
        std::memcpy(ptrUstring, domainName.data(), domainName.size() * sizeof(wchar_t));
        request->DomainName = WCharToUString(reinterpret_cast<wchar_t*>(ptrUstring));

        ptrUstring = ptrUstring + ((domainName.length() + 1) * sizeof(wchar_t));
        std::memcpy(ptrUstring, accountName.data(), accountName.size() * sizeof(wchar_t));
        request->AccountName = WCharToUString(reinterpret_cast<wchar_t*>(ptrUstring));

        ptrUstring = ptrUstring + ((accountName.length() + 1) * sizeof(wchar_t));
        std::memcpy(ptrUstring, newPassword.data(), newPassword.size() * sizeof(wchar_t));
        request->NewPassword = WCharToUString(reinterpret_cast<wchar_t*>(ptrUstring));

        PMSV1_0_CHANGEPASSWORD_RESPONSE response{ nullptr };
        auto result{ CallPackage(requestBytes, reinterpret_cast<void**>(&response)) };
        if (result) {
            lsa->out << "PasswordInfoValid    : " << response->PasswordInfoValid << std::endl;
            auto& DomainPasswordInfo{ response->DomainPasswordInfo };
            lsa->out << "MinPasswordLength    : " << DomainPasswordInfo.MinPasswordLength << std::endl;
            lsa->out << "PasswordHistoryLength: " << DomainPasswordInfo.PasswordHistoryLength << std::endl;
            lsa->out << "PasswordProperties   : " << DomainPasswordInfo.PasswordProperties << std::endl;
            lsa->out << "MaxPasswordAge       : " << DomainPasswordInfo.MaxPasswordAge.QuadPart << std::endl;
            lsa->out << "MinPasswordAge       : " << DomainPasswordInfo.MinPasswordAge.QuadPart << std::endl;
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::ClearCachedCredentials() const {
        CLEAR_CACHED_CREDENTIALS_REQUEST request = { MsV1_0ClearCachedCredentials };
        void* response;
        return CallPackage(request, &response);
    }

    bool Api::DecryptDpapiMasterKey() const {
        return 1;
    }

    bool Api::DeleteTbalSecrets() const {
        DELETE_TBAL_SECRETS_REQUEST request = { MsV1_0DeleteTbalSecrets };
        void* response{ nullptr };
        return CallPackage(request, &response);
    }

    bool Api::DeriveCredential(PLUID luid, ULONG type, const std::vector<byte>& mixingBits) const {
        size_t requestLength{ sizeof(MSV1_0_DERIVECRED_REQUEST) + mixingBits.size() };
        std::string requestBytes(requestLength, '\0');
        auto request{ reinterpret_cast<PMSV1_0_DERIVECRED_REQUEST>(requestBytes.data()) };
        request->MessageType = MsV1_0DeriveCredential;
        request->LogonId.LowPart = luid->LowPart;
        request->LogonId.HighPart = luid->HighPart;
        request->DeriveCredType = static_cast<ULONG>(type);
        request->DeriveCredInfoLength = mixingBits.size();
        std::memcpy(request->DeriveCredSubmitBuffer, mixingBits.data(), mixingBits.size());
        DERIVECRED_RESPONSE* response;
        auto result{ CallPackage(request, requestLength, &response) };
        if (result) {
            std::string cred(reinterpret_cast<const char*>(&response->DeriveCredReturnBuffer), response->DeriveCredInfoLength);
            OutputHex(lsa->out, "Derived Cred", cred);
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::EnumerateUsers() const {
        ENUMUSERS_REQUEST request = { MsV1_0EnumerateUsers };
        ENUMUSERS_RESPONSE* response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            auto count{ response->NumberOfLoggedOnUsers };
            lsa->out << "NumberOfLoggedOnUsers: " << count << std::endl;
            lsa->out << "LogonIds             : ";
            for (size_t index{ 0 }; index < count; index++) {
                lsa->out << "0x" << reinterpret_cast<LARGE_INTEGER*>(response->LogonIds)[index].QuadPart << ((index < (size_t(count) - 1)) ? ", " : "");
            }
            lsa->out << std::endl
                     << "EnumHandles          : ";
            for (size_t index{ 0 }; index < count; index++) {
                lsa->out << "0x" << reinterpret_cast<ULONG*>(response->EnumHandles)[index] << ((index < (size_t(count) - 1)) ? ", " : "");
            }
            lsa->out << std::endl;
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::GenericPassthrough(const std::wstring& domainName, const std::wstring& packageName, std::vector<byte>& data) const {
        std::vector<byte> requestBytes(sizeof(PASSTHROUGH_REQUEST) + (domainName.size() + packageName.size()) * sizeof(wchar_t) + data.size(), 0);
        auto request{ reinterpret_cast<MSV1_0_PASSTHROUGH_REQUEST*>(requestBytes.data()) };
        request->MessageType = MsV1_0GenericPassthrough;
        request->DomainName.Length = domainName.size() * sizeof(wchar_t);
        request->DomainName.MaximumLength = request->DomainName.Length;
        auto buffer{ reinterpret_cast<wchar_t*>(request + 1) };
        std::memcpy(buffer, domainName.data(), domainName.length() * sizeof(wchar_t));
        request->DomainName.Buffer = buffer;
        request->PackageName.Length = packageName.size() * sizeof(wchar_t);
        request->PackageName.MaximumLength = request->PackageName.Length;
        buffer = buffer + domainName.size();
        std::memcpy(buffer, packageName.data(), packageName.length() * sizeof(wchar_t));
        request->PackageName.Buffer = buffer;
        request->DataLength = data.size();
        buffer = buffer + packageName.size();
        std::memcpy(buffer, data.data(), data.size());
        request->LogonData = reinterpret_cast<PUCHAR>(buffer);
        PASSTHROUGH_RESPONSE* response;
        auto result{ CallPackage(*request, &response) };
        if (result) {
            data.resize(sizeof(response) + response->DataLength);
            std::memcpy(data.data(), response, sizeof(response) + response->DataLength);
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::GetCredentialKey(PLUID luid) const {
        MSV1_0_GETCREDKEY_REQUEST request = { MsV1_0GetCredentialKey };
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        PMSV1_0_GETCREDKEY_RESPONSE response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            auto credKeyHelper{ reinterpret_cast<PCREDENTIAL_KEY_HELPER>(response->CredKeyReturnBuffer) };
            std::string localKey(reinterpret_cast<const char*>(credKeyHelper->LocalUserKey.Data), MSV1_0_CREDENTIAL_KEY_LENGTH);
            OutputHex(lsa->out, "Local CredKey (SHA OWF)  ", localKey);
            // Check if the older NT OWF domain cred key or the newer secure domain cred key is being used
            std::string domainKey(reinterpret_cast<const char*>(credKeyHelper->DomainUserKey.Data), MSV1_0_CREDENTIAL_KEY_LENGTH);
            if (domainKey.length() > MSV1_0_OWF_PASSWORD_LENGTH) {
                if (localKey.size() == domainKey.size() && !std::memcmp(localKey.data(), domainKey.data(), domainKey.size())) {
                    std::cout << "Domain CredKey: Not calculated yet for logon session. Reported as SHA OWF." << std::endl;
                } else {
                    OutputHex(lsa->out, "Domain CredKey (\"Secure\")", domainKey);
                }
            } else {
                OutputHex(lsa->out, "Domain CredKey (NT OWF)  ", domainKey);
            }
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::GetStrongCredentialKey(PLUID luid, bool isProtectedUser) const {
        MSV1_0_GETSTRONGCREDKEY_REQUEST request = { MsV1_0GetStrongCredentialKey };
        request.RequestType = MSV1_0_GETSTRONGCREDKEY_USE_LOGON_ID;
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        request.Flags = isProtectedUser;
        PMSV1_0_GETSTRONGCREDKEY_RESPONSE response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            auto credKeyHelper{ reinterpret_cast<PCREDENTIAL_KEY_HELPER>(response->CredKeyReturnBuffer) };
            if (credKeyHelper->LocalUserKey.Data[0]) {
                std::string key(reinterpret_cast<const char*>(credKeyHelper->LocalUserKey.Data), MSV1_0_CREDENTIAL_KEY_LENGTH);
                OutputHex(lsa->out, "Local CredKey (SHA OWF)", key);
            } else {
                std::string key(reinterpret_cast<const char*>(credKeyHelper->DomainUserKey.Data), MSV1_0_CREDENTIAL_KEY_LENGTH);
                OutputHex(lsa->out, "Domain CredKey (NT OWF/\"Secure\")", key);
            }
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::GetUserInfo(PLUID luid) const {
        GETUSERINFO_REQUEST request = { MsV1_0GetUserInfo };
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        GETUSERINFO_RESPONSE* response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            lsa->out << "LogonType      : " << response->LogonType << std::endl;
            auto offset{ reinterpret_cast<byte*>(response + 1) };
            auto sidLength{ reinterpret_cast<byte*>(response->UserName.Buffer) - offset };
            UNICODE_STRING sidString = { 0 };
            if (RtlConvertSidToUnicodeString(&sidString, offset, true) == STATUS_SUCCESS) {
                std::wcout << L"UserSid        : " << sidString.Buffer << std::endl;
                RtlFreeUnicodeString(&sidString);
            }
            offset = offset + sidLength;
            std::wcout << L"UserName       : " << ToWString(&response->UserName) << std::endl;
            offset = offset + response->UserName.Length;
            std::wcout << L"LogonDomainName: " << ToWString(&response->LogonDomainName) << std::endl;
            offset = offset + response->LogonServer.Length;
            std::wcout << L"LogonServer    : " << ToWString(&response->LogonServer) << std::endl;
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::Lm20ChallengeRequest() const {
        MSV1_0_LM20_CHALLENGE_REQUEST request = { MsV1_0Lm20ChallengeRequest };
        PMSV1_0_LM20_CHALLENGE_RESPONSE response;
        bool result{ CallPackage(request, &response) };
        if (result) {
            std::string challenge(reinterpret_cast<const char*>(&response->ChallengeToClient), sizeof(response->ChallengeToClient));
            OutputHex(lsa->out, "Challenge To Client", challenge);
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::Lm20GetChallengeResponse(ULONG flags, PLUID luid, const std::vector<byte>& challenge) const {
        MSV1_0_GETCHALLENRESP_REQUEST request = { MsV1_0Lm20GetChallengeResponse };
        request.ParameterControl = flags;
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        std::memcpy(request.ChallengeToClient, challenge.data(), std::min(sizeof(request.ChallengeToClient), challenge.size()));
        PMSV1_0_GETCHALLENRESP_RESPONSE response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            auto buffer{ reinterpret_cast<const char*>(response->CaseSensitiveChallengeResponse.Buffer) };
            std::string caseSensitiveResponse(buffer, buffer + (response->CaseSensitiveChallengeResponse.Length));
            OutputHex(lsa->out, "CaseSensitiveChallengeResponse  ", caseSensitiveResponse);
            buffer = reinterpret_cast<const char*>(response->CaseInsensitiveChallengeResponse.Buffer);
            std::string caseInensitiveResponse(buffer, buffer + (response->CaseInsensitiveChallengeResponse.Length));
            OutputHex(lsa->out, "CaseInsensitiveChallengeResponse", caseInensitiveResponse);
            std::wcout << L"UserName                              : " << ToWString(&response->UserName) << std::endl;
            std::wcout << L"LogonDomainName                       : " << ToWString(&response->LogonDomainName) << std::endl;
            std::string userSessionKey(reinterpret_cast<const char*>(response->UserSessionKey), sizeof(response->UserSessionKey));
            OutputHex(lsa->out, "UserSessionKey                  ", userSessionKey);
            std::string lanmanSessionKey(reinterpret_cast<const char*>(response->LanmanSessionKey), sizeof(response->LanmanSessionKey));
            OutputHex(lsa->out, "LanmanSessionKey                ", lanmanSessionKey);
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::ProvisionTbal(PLUID luid) const {
        PROVISION_TBAL_REQUEST request = { MsV1_0ProvisionTbal };
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        void* response{ nullptr };
        return CallPackage(request, &response);
    }

    bool Api::SetProcessOption(ULONG options, bool disable) const {
        SETPROCESSOPTION_REQUEST request = { MsV1_0SetProcessOption };
        request.ProcessOptions = static_cast<ULONG>(options);
        request.DisableOptions = disable;
        void* response{ nullptr };
        return CallPackage(request, &response);
    }

    bool Api::CallPackage(const std::string& submitBuffer, void** returnBuffer) const {
        if (lsa->Connected()) {
            return lsa->CallPackage(MSV1_0_PACKAGE_NAME, submitBuffer, returnBuffer);
        }
        return false;
    }

    template<typename _Request, typename _Response>
    bool Api::CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const {
        std::string stringSubmitBuffer(reinterpret_cast<const char*>(&submitBuffer), sizeof(decltype(submitBuffer)));
        return CallPackage(stringSubmitBuffer, reinterpret_cast<void**>(returnBuffer));
    }

    template<typename _Request, typename _Response>
    bool Api::CallPackage(_Request* submitBuffer, size_t submitBufferLength, _Response** returnBuffer) const {
        std::string stringSubmitBuffer(reinterpret_cast<const char*>(submitBuffer), submitBufferLength);
        return CallPackage(stringSubmitBuffer, reinterpret_cast<void**>(returnBuffer));
    }
}