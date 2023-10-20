#include <Windows.h>
#include <cloudap.hpp>
#include <iostream>
#include <lsa.hpp>
#include <sstream>
#include <string>

namespace Cloudap {
    Proxy::Proxy(const std::shared_ptr<Lsa>& lsa)
        : lsa(lsa) {
    }

    bool Proxy::CallPluginGeneric(const GUID* plugin, const std::string& json, void** returnBuffer, size_t* returnBufferLength) const {
        size_t requestLength{ sizeof(CALL_PLUGIN_GENERIC_REQUEST) + json.size() + 1 + 0x1b }; // 0x1b is the sizeof some struct checked in cloudap!CloudAPCallPluginGeneric
        auto request{ reinterpret_cast<CALL_PLUGIN_GENERIC_REQUEST*>(std::malloc(requestLength)) };
        std::memset(request, 0, requestLength);
        request->MessageType = PROTOCOL_MESSAGE_TYPE::CallPluginGeneric;
        std::memcpy(&request->Package, plugin, sizeof(GUID));
        request->BufferLength = json.size() + 1;
        std::memcpy(request->Buffer, json.data(), json.length());
        request->Buffer[json.length()] = '\0';
        if (lsa->Connected()) {
            std::string stringSubmitBuffer(reinterpret_cast<const char*>(request), requestLength);
            return lsa->CallPackage(CLOUDAP_NAME_A, stringSubmitBuffer, returnBuffer, returnBufferLength);
        }
        return false;
    }

    bool Proxy::DisableOptimizedLogon(PLUID luid) const {
        DISABLE_OPTIMIZED_LOGON_REQUEST request;
        request.Luid.LowPart = luid->LowPart;
        request.Luid.HighPart = luid->HighPart;
        void* response;
        return CallPackage(request, &response);
    }

    bool Proxy::GenARSOPwd() const {
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::GenARSOPwd);
    }

    bool Proxy::GetAccountInfo() const { //xxx
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::GetAccountInfo);
    }

    bool Proxy::GetAuthenticatingProvider(PLUID luid) const {
        GET_TOKEN_BLOB_REQUEST request;
        request.Luid.LowPart = luid->LowPart;
        request.Luid.HighPart = luid->HighPart;
        GET_AUTHENTICATION_PROVIDER_RESPONSE* response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            RPC_WSTR providerString;
            (void)UuidToStringW(&response->provider, &providerString);
            lsa->out << "Provider: " << providerString << std::endl;
            RpcStringFreeW(&providerString);
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Proxy::GetDpApiCredKeyDecryptStatus(PLUID luid) const {
        GET_DP_API_CRED_KEY_DECRYPT_STATUS_REQUEST request;
        request.Luid.LowPart = luid->LowPart;
        request.Luid.HighPart = luid->HighPart;
        GET_DP_API_CRED_KEY_DECRYPT_STATUS_RESPONSE* response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            lsa->out << "IsDecrypted: " << response->IsDecrypted << std::endl;
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Proxy::GetPublicCachedInfo() const {
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::GetPublicCachedInfo);
    }

    bool Proxy::GetPwdExpiryInfo(PLUID luid) const {
        GET_PWD_EXPIRY_INFO_REQUEST request;
        request.Luid.LowPart = luid->LowPart;
        request.Luid.HighPart = luid->HighPart;
        GET_PWD_EXPIRY_INFO_RESPONSE* response;
        size_t returnLength;
        auto result{ CallPackage(request, &response, &returnLength) };
        if (result) {
            FILETIME forever{ 0xd5969fff, 0x7fffff36 };
            if (response->PwdExpirationTime.dwHighDateTime == forever.dwHighDateTime && response->PwdExpirationTime.dwLowDateTime == forever.dwLowDateTime) {
                std::wcout << "PwdExpirationTime: Never" << std::endl;
            } else {
                SYSTEMTIME systemTime = { 0 };
                FileTimeToSystemTime(&response->PwdExpirationTime, &systemTime);
                auto size{ GetDateFormatW(LOCALE_USER_DEFAULT, DATE_LONGDATE, &systemTime, nullptr, nullptr, 0) };
                std::vector<wchar_t> formattedTime(size, 0);
                if (GetDateFormatW(LOCALE_USER_DEFAULT, DATE_LONGDATE, &systemTime, nullptr, formattedTime.data(), formattedTime.size())) {
                    std::wcout << "PwdExpirationTime: " << std::wstring(formattedTime.data()) << std::endl;
                }
            }
            std::wcout << "PwdResetUrl: " << std::wstring(response->PwdResetUrl) << std::endl;
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Proxy::GetTokenBlob(PLUID luid) const {
        GET_TOKEN_BLOB_REQUEST request;
        request.Luid.LowPart = luid->LowPart;
        request.Luid.HighPart = luid->HighPart;
        char* response;
        size_t returnBufferLength;
        auto result{ CallPackage(request, &response, &returnBufferLength) };
        if (result) {
            OutputHex(lsa->out, "TokenBlob", std::string(response, returnBufferLength));
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Proxy::GetUnlockKeyType(PLUID luid) const {
        GET_UNLOCK_KEY_TYPE_REQUEST request;
        request.Luid.LowPart = luid->LowPart;
        request.Luid.HighPart = luid->HighPart;
        GET_UNLOCK_KEY_TYPE_RESPONSE* response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            lsa->out << "Type: " << response->Type << std::endl;
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Proxy::IsCloudToOnPremTgtPresentInCache(PLUID luid) const {
        IS_CLOUD_TO_ON_PREM_TGT_PRESENT_IN_CACHE_REQUEST request;
        request.Luid.LowPart = luid->LowPart;
        request.Luid.HighPart = luid->HighPart;
        IS_CLOUD_TO_ON_PREM_TGT_PRESENT_IN_CACHE_RESPONSE* response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            lsa->out << "IsPresent: " << response->IsPresent << std::endl;
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Proxy::ProfileDeleted() const {
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::ProfileDeleted);
    }

    bool Proxy::ProvisionNGCNode() const {
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::ProvisionNGCNode);
    }

    bool Proxy::RefreshTokenBlob() const {
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::RefreshTokenBlob);
    }

    bool Proxy::ReinitPlugin() const {
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::ReinitPlugin);
    }

    bool Proxy::RenameAccount() const { //xxx
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::RenameAccount);
    }

    bool Proxy::SetTestParas(ULONG TestFlags) const {
        SET_TEST_PARAS_REQUEST request;
        request.Flags = TestFlags;
        void* response{ nullptr };
        auto status{ CallPackage(&request, &response) };
        return status;
    }

    bool Proxy::TransferCreds(PLUID sourceLuid, PLUID destinationLuid) const {
        TRANSFER_CRED_REQUEST request;
        request.OriginLogonId.LowPart = sourceLuid->LowPart;
        request.OriginLogonId.HighPart = sourceLuid->HighPart;
        request.DestinationLogonId.LowPart = destinationLuid->LowPart;
        request.DestinationLogonId.HighPart = destinationLuid->HighPart;
        void* response;
        return CallPackage(request, &response);
    }

    bool Proxy::CallPackage(PROTOCOL_MESSAGE_TYPE MessageType) const {
        auto request{ static_cast<ULONG>(MessageType) };
        void* response{ nullptr };
        return this->CallPackage(request, &response);
    }

    template<typename _Request, typename _Response>
    bool Proxy::CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const {
        size_t returnBufferLength;
        return CallPackage(submitBuffer, returnBuffer, &returnBufferLength);
    }

    template<typename _Request, typename _Response>
    bool Proxy::CallPackage(const _Request& submitBuffer, _Response** returnBuffer, size_t* returnBufferLength) const {
        if (lsa->Connected()) {
            std::string stringSubmitBuffer(reinterpret_cast<const char*>(&submitBuffer), sizeof(decltype(submitBuffer)));
            return lsa->CallPackage(CLOUDAP_NAME_A, stringSubmitBuffer, reinterpret_cast<void**>(returnBuffer));
        }
        return false;
    }
}

namespace Cloudap::Aad {
    Proxy::Proxy(const std::shared_ptr<Lsa>& lsa)
        : Cloudap::Proxy(lsa) {
    }

    bool Proxy::GetUnlockKey(AUTHORITY_TYPE authority) const {
        std::stringstream stream;
        stream << "{\"call\":3,\"authoritytype\":" << authority << "}";
        void* returnBuffer{ nullptr };
        size_t returnBufferLength{ 0 };
        auto result{ CallPluginGeneric(&AadGlobalIdProviderGuid, stream.str(), &returnBuffer, &returnBufferLength) };
        if (result) {
            lsa->out << "UnlockKey: " << reinterpret_cast<char*>(returnBuffer) << std::endl;
            LsaFreeReturnBuffer(returnBuffer);
        }
        return result;
    }

    bool Proxy::RefreshToken() const {
        void* returnBuffer{ nullptr };
        size_t returnBufferLength{ 0 };
        auto aaa = CallPluginGeneric(&AadGlobalIdProviderGuid, "{\"call\":11}", &returnBuffer, &returnBufferLength);
        std::cout << returnBuffer << std::endl;
        return aaa;
    }
}