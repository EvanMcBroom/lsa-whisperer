#define _NTDEF_ // Required to include both Ntsecapi and Winternl
#include <Winternl.h>
#include <codecvt>
#include <crypt.hpp>
#include <iomanip>
#include <iostream>
#include <lsa.hpp>
#include <msv1_0.hpp>
#include <string>
#include <vector>

#define STATUS_SUCCESS 0

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

    constexpr size_t RoundUp(size_t count, size_t powerOfTwo) {
        return (count + powerOfTwo - 1) & (~powerOfTwo - 1);
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
    Proxy::Proxy(const std::shared_ptr<Lsa>& lsa)
        : lsa(lsa) {
    }

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

    bool Proxy::ChangeCachedPassword(const std::wstring& domainName, const std::wstring& accountName, const std::wstring& newPassword) const {
        // Based off of schedsvc!NotifyLsaOfPasswordChange
        auto requestSize{ sizeof(MSV1_0_CHANGEPASSWORD_REQUEST) + ((domainName.length() + accountName.length() + newPassword.length() + 3) * sizeof(wchar_t)) };
        std::string requestBytes(requestSize, '\0');
        auto request{ reinterpret_cast<PMSV1_0_CHANGEPASSWORD_REQUEST>(requestBytes.data()) };
        request->MessageType = static_cast<MSV1_0_PROTOCOL_MESSAGE_TYPE>(PROTOCOL_MESSAGE_TYPE::ChangeCachedPassword);

        auto ptrUstring{ reinterpret_cast<std::byte*>(request + 1) };
        std::memcpy(ptrUstring, domainName.data(), domainName.size() * sizeof(wchar_t));
        request->DomainName = WCharToUString(reinterpret_cast<wchar_t*>(ptrUstring));

        ptrUstring = ptrUstring + ((domainName.length() + 1) * sizeof(wchar_t));
        std::memcpy(ptrUstring, accountName.data(), accountName.size() * sizeof(wchar_t));
        request->AccountName = WCharToUString(reinterpret_cast<wchar_t*>(ptrUstring));

        ptrUstring = ptrUstring + ((accountName.length() + 1) * sizeof(wchar_t));
        std::memcpy(ptrUstring, newPassword.data(), newPassword.size() * sizeof(wchar_t));
        request->NewPassword = WCharToUString(reinterpret_cast<wchar_t*>(ptrUstring));

        MSV1_0_CHANGEPASSWORD_RESPONSE* response;
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

    bool Proxy::ClearCachedCredentials() const {
        CLEAR_CACHED_CREDENTIALS_REQUEST request;
        void* response;
        return CallPackage(request, &response);
    }

    bool Proxy::DecryptDpapiMasterKey() const {
        return 1;
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

    bool Proxy::EnumerateUsers() const {
        ENUMUSERS_REQUEST request;
        ENUMUSERS_RESPONSE* response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            auto count{ response->NumberOfLoggedOnUsers };
            lsa->out << "NumberOfLoggedOnUsers: " << count << std::endl;
            lsa->out << "LogonIds             : ";
            for (size_t index{ 0 }; index < count; index++) {
                lsa->out << "0x" << reinterpret_cast<LARGE_INTEGER*>(response->LogonSessions)[index].QuadPart << ((index < (count - 1)) ? ", " : "");
            }
            lsa->out << std::endl
                     << "EnumHandles          : ";
            for (size_t index{ 0 }; index < count; index++) {
                lsa->out << "0x" << reinterpret_cast<ULONG*>(response->EnumHandles)[index] << ((index < (count - 1)) ? ", " : "");
            }
            lsa->out << std::endl;
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Proxy::GenericPassthrough(const std::wstring& domainName, const std::wstring& packageName, std::vector<byte>& data) const {
        std::vector<byte> requestBytes(sizeof(PASSTHROUGH_REQUEST) + (domainName.size() + packageName.size()) * sizeof(wchar_t) + data.size(), 0);
        auto request{ reinterpret_cast<PPASSTHROUGH_REQUEST>(requestBytes.data()) };
        request->MessageType = PROTOCOL_MESSAGE_TYPE::GenericPassthrough;
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

    bool Proxy::GetCredentialKey(PLUID luid) const {
        GET_CREDENTIAL_KEY_REQUEST request;
        request.LogonSession.LowPart = luid->LowPart;
        request.LogonSession.HighPart = luid->HighPart;
        GET_CREDENTIAL_KEY_RESPONSE* response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            std::string shaOwf(reinterpret_cast<const char*>(&response->ShaPassword), MSV1_0_SHA_PASSWORD_LENGTH);
            OutputHex(lsa->out, "Local CredKey (SHA OWF)  ", shaOwf);
            // If there is data past the length for the ShaOwf and the NtOwf, then the NtOwf offset will actually be the Dpapi key
            if (*reinterpret_cast<DWORD*>(&response->Key2[MSV1_0_OWF_PASSWORD_LENGTH])) {
                std::string dpapiKey(reinterpret_cast<const char*>(&response->Key2), MSV1_0_CREDENTIAL_KEY_LENGTH);
                if (shaOwf.size() == dpapiKey.size() && !std::memcmp(shaOwf.data(), dpapiKey.data(), dpapiKey.size())) {
                    std::cout << "Domain CredKey: Not calculated yet for logon session. Reported as SHA OWF." << std::endl;
                } else {
                    OutputHex(lsa->out, "Domain CredKey (\"Secure\")", dpapiKey);
                }
            } else {
                std::string ntOwf(reinterpret_cast<const char*>(&response->Key2), MSV1_0_OWF_PASSWORD_LENGTH);
                OutputHex(lsa->out, "Domain CredKey (NT OWF)  ", ntOwf);
            }
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Proxy::GetStrongCredentialKey(PLUID luid, bool isProtectedUser) const {
        GET_STRONG_CREDENTIAL_KEY_REQUEST request;
        std::memset(&request, '\0', sizeof(request));
        request.MessageType = PROTOCOL_MESSAGE_TYPE::GetStrongCredentialKey;
        request.Version = 0;
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        request.IsProtectedUser = isProtectedUser;
        GET_STRONG_CREDENTIAL_KEY_RESPONSE* response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            if (*reinterpret_cast<DWORD*>(&response->ShaPassword)) {
                std::string shaOwf(reinterpret_cast<const char*>(&response->ShaPassword), MSV1_0_SHA_PASSWORD_LENGTH);
                OutputHex(lsa->out, "Local CredKey (SHA OWF)", shaOwf);
            } else {
                std::string dpapiKey(reinterpret_cast<const char*>(&response->Key2), MSV1_0_CREDENTIAL_KEY_LENGTH);
                OutputHex(lsa->out, "Domain CredKey (NT OWF/\"Secure\")", dpapiKey);
            }
            LsaFreeReturnBuffer(response);
        }
        return result;

    }

    bool Proxy::GetUserInfo(PLUID luid) const {
        GETUSERINFO_REQUEST request;
        request.LogonSession.LowPart = luid->LowPart;
        request.LogonSession.HighPart = luid->HighPart;
        GETUSERINFO_RESPONSE* response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            lsa->out << "LogonType      : " << response->LogonType << std::endl;
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
        LM20_CHALLENGE_REQUEST_REQUEST request;
        LM20_CHALLENGE_REQUEST_RESPONSE* response;
        bool result{ CallPackage(request, &response) };
        if (result) {
            std::string challenge(reinterpret_cast<const char*>(&response->ChallengeToClient), sizeof(response->ChallengeToClient));
            OutputHex(lsa->out, "Challenge To Client", challenge);
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Proxy::Lm20GetChallengeResponse(ULONG flags, PLUID luid, const std::vector<byte>& challenge) const {
        LM20_GET_CHALLENGE_RESPONSE_REQUEST request;
        std::memset(&request, '\0', sizeof(request));
        request.MessageType = PROTOCOL_MESSAGE_TYPE::Lm20GetChallengeResponse;
        request.ParameterControl = flags;
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        std::memcpy(request.ChallengeToClient, challenge.data(), std::min(sizeof(request.ChallengeToClient), challenge.size()));
        LM20_GET_CHALLENGE_RESPONSE_RESPONSE* response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            auto buffer{ reinterpret_cast<const char*>(response->CaseSensitiveChallengeResponse.Buffer) };
            std::string caseSensitiveResponse(buffer, buffer + (response->CaseSensitiveChallengeResponse.Length));
            OutputHex(lsa->out, "CaseSensitiveChallengeResponse  ", caseSensitiveResponse);
            buffer = reinterpret_cast<const char*>(response->CaseInsensitiveChallengeResponse.Buffer);
            std::string caseInensitiveResponse(buffer, buffer + (response->CaseInsensitiveChallengeResponse.Length));
            OutputHex(lsa->out, "CaseInsensitiveChallengeResponse", caseInensitiveResponse);
            if (response->UserName.Buffer) {
                std::wcout << L"UserName                              : " << response->UserName.Buffer << std::endl;
            } else {
                std::wcout << L"UserName                              : nullptr" << std::endl;
            }
            if (response->LogonDomainName.Buffer) {
                std::wcout << L"LogonDomainName                       : " << response->LogonDomainName.Buffer << std::endl;
            } else {
                std::wcout << L"LogonDomainName                       : nullptr" << std::endl;
            }
            std::string userSessionKey(reinterpret_cast<const char*>(response->UserSessionKey), sizeof(response->UserSessionKey));
            OutputHex(lsa->out, "UserSessionKey                  ", userSessionKey);
            std::string lanmanSessionKey(reinterpret_cast<const char*>(response->LanmanSessionKey), sizeof(response->LanmanSessionKey));
            OutputHex(lsa->out, "LanmanSessionKey                ", lanmanSessionKey);
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
}