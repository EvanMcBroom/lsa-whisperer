#include <Windows.h>
#define _NTDEF_ // Required to include both Ntsecapi and Winternl
#include <Winternl.h>
#include <cache.hpp>
#include <crypt.hpp>
#include <iomanip>
#include <iostream>
#include <magic_enum.hpp>
#include <msv1_0.hpp>
#include <string>
#include <vector>
#include <netlogon.hpp>

#pragma comment(lib, "Ntdll.lib")
#pragma comment(lib, "Secur32.lib")

#define STATUS_SUCCESS 0

namespace {
    UnicodeString::UnicodeString(std::wstring data) {
        RtlInitUnicodeString(this, data.c_str());
    }
    
    UnicodeString::~UnicodeString() {
        RtlFreeUnicodeString(this);
    }

    bool CallPackage(const std::string& package, const std::string& submitBuffer, void** returnBuffer) {
        bool result{ false };
        if (returnBuffer) {
            *returnBuffer = (void*)0x0;
            HANDLE lsaHandle;
            if (SUCCEEDED(LsaConnectUntrusted(&lsaHandle))) {
                LSA_STRING packageName;
                RtlInitString(reinterpret_cast<PSTRING>(&packageName), package.data());
                ULONG authPackage;
                if (SUCCEEDED(LsaLookupAuthenticationPackage(lsaHandle, &packageName, &authPackage))) {
                    PVOID returnBuffer2;
                    ULONG returnBufferLength;
                    NTSTATUS protocolStatus;
                    OutputHex("InputData", submitBuffer);
                    auto status{ LsaCallAuthenticationPackage(lsaHandle, authPackage, reinterpret_cast<PVOID>(const_cast<char*>(submitBuffer.data())), submitBuffer.size(), &returnBuffer2, &returnBufferLength, &protocolStatus) };
                    if (SUCCEEDED(status)) {
                        if (protocolStatus >= 0) {
                            OutputHex("OutputData", std::string(reinterpret_cast<const char*>(returnBuffer2), returnBufferLength));
                            std::cout << std::endl;
                            *returnBuffer = returnBuffer2;
                            result = true;
                        }
                        else {
                            std::cout << "OutputData[0]: nullptr" << std::endl;
                            *returnBuffer = nullptr;
                            LsaFreeReturnBuffer(returnBuffer);
                        }
                        std::cout << "ProtocolStatus: 0x" << protocolStatus << std::endl;
                    }
                    else {
                        std::cout << "Error: " << status << std::endl;
                    }
                }
                LsaDeregisterLogonProcess(lsaHandle);
            }
        }
        return result;
    }

    void OutputHex(const std::string& prompt, const std::string& data) {
        std::cout << prompt << "[" << data.length() << "]: ";
        for (const auto& item : data) {
            std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(static_cast<unsigned char>(item));
        }
        std::cout << std::endl;
    }
}

namespace MSV1_0 {
    bool CallPackage(const std::string& submitBuffer, void** returnBuffer) {
        return ::CallPackage(MSV1_0_PACKAGE_NAME, submitBuffer, returnBuffer);
    }

    template<typename _Request, typename _Response>
    bool CallPackage(const _Request& submitBuffer, _Response** returnBuffer) { // submitBufferPadding
        std::string stringSubmitBuffer(reinterpret_cast<const char*>(&submitBuffer), sizeof(decltype(submitBuffer)));
        return CallPackage(stringSubmitBuffer, reinterpret_cast<void**>(returnBuffer));
    }

    //template<typename _Request, typename _Response>
    //bool CallPackage(const _Request&& submitBuffer, _Response** returnBuffer) {
    //    return CallPackage(std::forward<_Request>(submitBuffer), 0, returnBuffer);
    //}

    bool CacheLogon(void* logonInfo, void* validationInfo, const std::vector<byte>& supplementalCacheData, ULONG flags) {
        MSV1_0::CACHE_LOGON_REQUEST request;
        request.LogonInformation = logonInfo;
        request.ValidationInformation = validationInfo;
        request.SupplementalCacheData = const_cast<byte*>(supplementalCacheData.data());
        request.SupplementalCacheDataLength = supplementalCacheData.size();
        void* response;
        return CallPackage(request, &response);
    }

    bool CacheLookupEx(const std::wstring username, const std::wstring domain, MSV1_0::CacheLookupCredtype type, const std::string credential) {
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

    bool ChangeCachedPassword(const std::wstring& domainName, const std::wstring& accountName, const std::wstring& oldPassword, const std::wstring& newPassword, bool impersonating) {
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
            std::cout << "PasswordInfoValid    : " << response->PasswordInfoValid << std::endl;
            auto& DomainPasswordInfo{ response->DomainPasswordInfo };
            std::cout << "MinPasswordLength    : " << DomainPasswordInfo.MinPasswordLength << std::endl;
            std::cout << "PasswordHistoryLength: " << DomainPasswordInfo.PasswordHistoryLength << std::endl;
            std::cout << "PasswordProperties   : " << DomainPasswordInfo.PasswordProperties << std::endl;
            std::cout << "MaxPasswordAge       : " << DomainPasswordInfo.MaxPasswordAge.QuadPart << std::endl;
            std::cout << "MinPasswordAge       : " << DomainPasswordInfo.MinPasswordAge.QuadPart << std::endl;
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool ClearCachedCredentials() {
        CLEAR_CACHED_CREDENTIALS_REQUEST request;
        void* response;
        return CallPackage(request, &response);
    }

    bool DecryptDpapiMasterKey() {
        DECRYPT_DPAPI_MASTER_KEY_REQUEST request;
        DECRYPT_DPAPI_MASTER_KEY_RESPONSE* response;
        auto result{ CallPackage(request, &response) };
        // Parse response
        return result;
    }

    bool DeleteTbalSecrets() {
        DELETE_TBAL_SECRETS_REQUEST request;
        void* response{ nullptr };
        return CallPackage(request, &response);
    }

    bool EnumerateUsers() {
        ENUMUSERS_REQUEST request;
        ENUMUSERS_RESPONSE* response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            auto count{ response->NumberOfLoggedOnUsers };
            std::cout << "NumberOfLoggedOnUsers: " << count << std::endl;
            std::cout << "LogonIds             : ";
            for (size_t index{ 0 }; index < count; index++) {
                std::cout << "0x" << reinterpret_cast<LARGE_INTEGER*>(response->LogonIds)[index].QuadPart << ((index < (count - 1)) ? ", " : "");
            }
            std::cout << std::endl << "EnumHandles          : ";
            for (size_t index{ 0 }; index < count; index++) {
                std::cout << "0x" << reinterpret_cast<ULONG*>(response->EnumHandles)[index] << ((index < (count - 1)) ? ", " : "");
            }
            std::cout << std::endl;
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool GenericPassthrough() {
        //GENERIC request;
        //TRANSFER_CRED_RESPONSE* response;
        //auto result{ CallPackage(request, &response) };
        // Parse response
        return false;
    }

    bool GetCredentialKey(PLUID luid) {
        GET_CREDENTIAL_KEY_REQUEST request;
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        GET_CREDENTIAL_KEY_RESPONSE* response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            std::cout << "Testing... GET_CREDENTIAL_KEY_RESPONSE size: " << sizeof(GET_CREDENTIAL_KEY_RESPONSE) << std::endl;
        }
        return result;
    }

    bool GetStrongCredentialKey() {
        GET_STRONG_CREDENTIAL_KEY_REQUEST request;
        GET_STRONG_CREDENTIAL_KEY_RESPONSE* response;
        auto result{ CallPackage(request, &response) };
        // Parse response
        return result;
    }

    bool GetUserInfo(PLUID luid) {
        GETUSERINFO_REQUEST request;
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        GETUSERINFO_RESPONSE* response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            std::cout << "LogonType      : " << magic_enum::enum_names<SECURITY_LOGON_TYPE>()[response->LogonType] << std::endl;
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

    bool ProvisionTbal(PLUID luid) {
        PROVISION_TBAL_REQUEST request;
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        void* response{ nullptr };
        return CallPackage(request, &response);
    }

    bool SetProcessOption(ProcessOption options, bool disable) {
        SETPROCESSOPTION_REQUEST request;
        request.ProcessOptions = static_cast<ULONG>(options);
        request.DisableOptions = disable;
        void* response;
        return CallPackage(request, &response);
    }

    bool TransferCred() {
        TRANSFER_CRED_REQUEST request;
        TRANSFER_CRED_RESPONSE* response;
        auto result{ CallPackage(request, &response) };
        // Parse response
        return result;
    }
}