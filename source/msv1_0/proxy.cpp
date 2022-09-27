#define _NTDEF_ // Required to include both Ntsecapi and Winternl
#include <Winternl.h>
#include <crypt.hpp>
#include <iomanip>
#include <iostream>
#include <lsa.hpp>
#include <magic_enum.hpp>
#include <msv1_0/cache.hpp>
#include <msv1_0/proxy.hpp>
#include <string>
#include <vector>
#include <netlogon.hpp>

#define STATUS_SUCCESS 0

namespace Msv1_0 {
    bool Proxy::CacheLogon(void* logonInfo, void* validationInfo, const std::vector<byte>& supplementalCacheData, ULONG flags) const {
        CACHE_LOGON_REQUEST request;
        request.LogonInformation = logonInfo;
        request.ValidationInformation = validationInfo;
        request.SupplementalCacheData = const_cast<byte*>(supplementalCacheData.data());
        request.SupplementalCacheDataLength = supplementalCacheData.size();
        void* response;
        return CallPackage(request, &response);
    }

    bool Proxy::CacheLookupEx(const std::wstring username, const std::wstring domain, CacheLookupCredType type, const std::string credential) const {
        CACHE_LOOKUP_EX_REQUEST request;
        UnicodeString userName{ username };
        request.UserName = userName;
        UnicodeString domainName{ domain };
        request.DomainName = domainName;
        request.CredentialType = type;
        request.CredentialInfoLength = credential.length();
        //&request.CredentialSubmitBuffer = credential.data();
        CACHE_LOOKUP_EX_RESPONSE* response;
        //auto result{ CallPackage(request, credential.length() - 1, &response) };
        if (1) {
            //response.
        }
        return 1;
    }

    bool Proxy::ChangeCachedPassword(const std::wstring& domainName, const std::wstring& accountName, const std::wstring& oldPassword, const std::wstring& newPassword, bool impersonating) const {
        CHANGE_CACHED_PASSWORD_REQUEST request;
        UnicodeString domainNameGuard{ domainName };
        request.DomainName = domainNameGuard;
        UnicodeString accountNameGuard{ accountName };
        request.AccountName = accountNameGuard;
        UnicodeString oldPasswordGuard{ oldPassword };
        request.OldPassword = oldPasswordGuard;
        UnicodeString newPasswordGuard{ newPassword };
        request.NewPassword = newPasswordGuard;
        request.Impersonating = impersonating;
        CHANGE_CACHED_PASSWORD_RESPONSE* response;
        auto result{ CallPackage(request, &response) };
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

    bool Proxy::ClearCachedCredentials() const {
        CLEAR_CACHED_CREDENTIALS_REQUEST request;
        void* response;
        return CallPackage(request, &response);
    }

    bool Proxy::DecryptDpapiMasterKey() const {
        DECRYPT_DPAPI_MASTER_KEY_REQUEST request;
        lsa->out << "Size: " << sizeof(request) << std::endl;
        DECRYPT_DPAPI_MASTER_KEY_RESPONSE* response;
        auto result{ CallPackage(request, &response) };
        // Parse response
        return result;
    }

    bool Proxy::DeleteTbalSecrets() const {
        DELETE_TBAL_SECRETS_REQUEST request;
        void* response{ nullptr };
        return CallPackage(request, &response);
    }

    bool Proxy::DeriveCredential(PLUID luid, DeriveCredType type, const std::vector<byte>& mixingBits) const {
        size_t requestLength{ sizeof(DERIVECRED_REQUEST) + mixingBits.size() };
        auto request{ reinterpret_cast<DERIVECRED_REQUEST*>(std::malloc(requestLength)) };
        request->MessageType = PROTOCOL_MESSAGE_TYPE::DeriveCredential;
        request->LogonSession.LowPart = luid->LowPart;
        request->LogonSession.HighPart = luid->HighPart;
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

    bool Proxy::EnumerateUsers(bool passthrough) const {
        ENUMUSERS_REQUEST request;
        ENUMUSERS_RESPONSE* response;
        bool result;
        if (passthrough) {
            std::vector<byte> data{ sizeof(decltype(request)), 0 };
            std::memcpy(data.data(), &request, sizeof(decltype(request)));
            GenericPassthrough(L"", MSV1_0_PACKAGE_NAMEW, data);
            response = reinterpret_cast<decltype(response)>(malloc(sizeof(ENUMUSERS_RESPONSE)));
            std::memcpy(response, data.data(), sizeof(decltype(response)));
        }
        else {
            result = CallPackage(request, &response);
        }
        if (result) {
            auto count{ response->NumberOfLoggedOnUsers };
            lsa->out << "NumberOfLoggedOnUsers: " << count << std::endl;
            lsa->out << "LogonIds             : ";
            for (size_t index{ 0 }; index < count; index++) {
                lsa->out << "0x" << reinterpret_cast<LARGE_INTEGER*>(response->LogonSessions)[index].QuadPart << ((index < (count - 1)) ? ", " : "");
            }
            lsa->out << std::endl << "EnumHandles          : ";
            for (size_t index{ 0 }; index < count; index++) {
                lsa->out << "0x" << reinterpret_cast<ULONG*>(response->EnumHandles)[index] << ((index < (count - 1)) ? ", " : "");
            }
            lsa->out << std::endl;
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Proxy::GenericPassthrough(const std::wstring& domainName, const std::wstring& packageName, std::vector<byte>& data) const {
        auto requestSize{ sizeof(MSV1_0_PASSTHROUGH_REQUEST)
            + (domainName.size() + 1) * sizeof(wchar_t)
            + (packageName.size() + 1) * sizeof(wchar_t)
            + data.size()
        };

        auto aa1 = offsetof(PASSTHROUGH_REQUEST, MessageType);
        auto aa2 = offsetof(PASSTHROUGH_REQUEST, DomainName);
        auto aa3 = offsetof(PASSTHROUGH_REQUEST, PackageName);
        auto aa4 = offsetof(PASSTHROUGH_REQUEST, DataLength);
        auto aa5 = offsetof(PASSTHROUGH_REQUEST, LogonData);
        auto aa6 = offsetof(PASSTHROUGH_REQUEST, Pad);


        auto request{ reinterpret_cast<PASSTHROUGH_REQUEST*>(malloc(requestSize)) };
        std::memset(request, '\0', requestSize);
        request->MessageType = PROTOCOL_MESSAGE_TYPE::GenericPassthrough;

        auto ptr{ reinterpret_cast<byte*>(request + 1) };
        request->DomainName.MaximumLength = request->DomainName.Length = domainName.size();
        request->DomainName.Buffer = reinterpret_cast<PWSTR>(ptr - reinterpret_cast<byte*>(request));
        std::memcpy(ptr, domainName.data(), domainName.size());

        ptr += (domainName.size() + 1) * sizeof(wchar_t);
        request->PackageName.MaximumLength = request->PackageName.Length = packageName.size();
        request->PackageName.Buffer = reinterpret_cast<PWSTR>(ptr - reinterpret_cast<byte*>(request));
        std::memcpy(ptr, packageName.data(), packageName.size());

        ptr += (packageName.size() + 1) * sizeof(wchar_t);
        request->DataLength = data.size();
        request->LogonData = reinterpret_cast<PUCHAR>(ptr - reinterpret_cast<byte*>(request));
        std::memcpy(ptr, data.data(), data.size());

        PASSTHROUGH_RESPONSE* response;
        std::string stringSubmitBuffer(reinterpret_cast<const char*>(request), requestSize);
        auto result{ CallPackage(stringSubmitBuffer, reinterpret_cast<void**>(&response)) };
        // Parse response
        return false;
    }

    bool Proxy::GetCredentialKey(PLUID luid) const {
        GET_CREDENTIAL_KEY_REQUEST request;
        request.LogonSession.LowPart = luid->LowPart;
        request.LogonSession.HighPart = luid->HighPart;
        GET_CREDENTIAL_KEY_RESPONSE* response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            std::string shaOwf(reinterpret_cast<const char*>(&response->CredentialData), MSV1_0_SHA_PASSWORD_LENGTH);
            OutputHex(lsa->out, "ShaOwf", shaOwf);
            // If there is data past the length for the ShaOwf and the NtOwf, then the NtOwf offset will actually be the Dpapi key
            if (*reinterpret_cast<DWORD*>(&response->CredentialData[MSV1_0_SHA_PASSWORD_LENGTH + MSV1_0_OWF_PASSWORD_LENGTH])) {
                std::string dpapiKey(reinterpret_cast<const char*>(&response->CredentialData[MSV1_0_SHA_PASSWORD_LENGTH]), MSV1_0_CREDENTIAL_KEY_LENGTH);
                OutputHex(lsa->out, "DpapiKey", dpapiKey);
            }
            else {
                std::string ntOwf(reinterpret_cast<const char*>(&response->CredentialData[MSV1_0_SHA_PASSWORD_LENGTH]), MSV1_0_OWF_PASSWORD_LENGTH);
                OutputHex(lsa->out, "NtOwf", ntOwf);
            }
        }
        return result;
    }

    bool Proxy::GetStrongCredentialKey() const {
        GET_STRONG_CREDENTIAL_KEY_REQUEST request;
        GET_STRONG_CREDENTIAL_KEY_RESPONSE* response;
        auto result{ CallPackage(request, &response) };
        // Parse response
        return result;
    }

    bool Proxy::GetUserInfo(PLUID luid) const {
        GETUSERINFO_REQUEST request;
        request.LogonSession.LowPart = luid->LowPart;
        request.LogonSession.HighPart = luid->HighPart;
        GETUSERINFO_RESPONSE* response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            lsa->out << "LogonType      : " << magic_enum::enum_names<SECURITY_LOGON_TYPE>()[response->LogonType] << std::endl;
            auto offset{ reinterpret_cast<byte*>(response + 1) };
            auto sidLength{ reinterpret_cast<byte*>(response->UserName.Buffer) - offset };
            UNICODE_STRING sidString;
            if (RtlConvertSidToUnicodeString(&sidString, offset, true) == STATUS_SUCCESS) {
                std::wcout << L"UserSid        : " << sidString.Buffer << std::endl;
                RtlFreeUnicodeString(&sidString);
            }
            offset = offset + sidLength;
            std::wcout << L"UserName       : " << response->UserName.Buffer << std::endl;
            offset = offset + response->UserName.Length;
            std::wcout << L"LogonDomainName: " << response->LogonDomainName.Buffer << std::endl;
            offset = offset + response->LogonServer.Length;
            std::wcout << L"LogonServer    : " << response->LogonServer.Buffer << std::endl;
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Proxy::Lm20ChallengeRequest() const {
        LM20_CHALLENGE_REQUEST request;
        LM20_CHALLENGE_RESPONSE* response;
        bool result{ CallPackage(request, &response) };
        if (result) {
            std::string challenge(reinterpret_cast<const char*>(&response->ChallengeToClient), sizeof(response->ChallengeToClient));
            OutputHex(lsa->out, "Challenge To Client", challenge);
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Proxy::ProvisionTbal(PLUID luid) const {
        PROVISION_TBAL_REQUEST request;
        request.LogonSession.LowPart = luid->LowPart;
        request.LogonSession.HighPart = luid->HighPart;
        void* response{ nullptr };
        return CallPackage(request, &response);
    }

    bool Proxy::SetProcessOption(ProcessOption options, bool disable) const {
        SETPROCESSOPTION_REQUEST request;
        request.ProcessOptions = static_cast<ULONG>(options);
        request.DisableOptions = disable;
        void* response;
        return CallPackage(request, &response);
    }

    bool Proxy::TransferCred(PLUID sourceLuid, PLUID destinationLuid) const {
        TRANSFER_CRED_REQUEST request;
        request.SourceLuid.LowPart = sourceLuid->LowPart;
        request.SourceLuid.HighPart = sourceLuid->HighPart;
        request.DestinationLuid.LowPart = destinationLuid->LowPart;
        request.DestinationLuid.HighPart = destinationLuid->HighPart;
        void* response;
        return CallPackage(request, &response);
    }

    bool Proxy::CallPackage(const std::string& submitBuffer, void** returnBuffer) const {
        if (lsa->Connected()) {
            return lsa->CallPackage(MSV1_0_PACKAGE_NAME, submitBuffer, returnBuffer);
        }
        return false;
    }

    template<typename _Request, typename _Response>
    bool Proxy::CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const {
        std::string stringSubmitBuffer(reinterpret_cast<const char*>(&submitBuffer), sizeof(decltype(submitBuffer)));
        return CallPackage(stringSubmitBuffer, reinterpret_cast<void**>(returnBuffer));
    }

    template<typename _Request, typename _Response>
    bool Proxy::CallPackage(_Request* submitBuffer, size_t submitBufferLength, _Response** returnBuffer) const {
        std::string stringSubmitBuffer(reinterpret_cast<const char*>(submitBuffer), submitBufferLength);
        return CallPackage(stringSubmitBuffer, reinterpret_cast<void**>(returnBuffer));
    }

    //template<typename _Request, typename _Response>
    //bool Proxy::CallPackage(const _Request&& submitBuffer, _Response** returnBuffer) {
    //    return CallPackage(std::forward<_Request>(submitBuffer), 0, returnBuffer);
    //}
}