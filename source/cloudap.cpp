#include <Windows.h>
#include <cloudap.hpp>
#include <iostream>
#include <lsa.hpp>
#include <sstream>
#include <string>

namespace {
    std::string CorrelationId() {
        UUID uuid;
        UuidCreate(&uuid);
        RPC_CSTR uuidString;
        if (UuidToStringA(&uuid, &uuidString) == RPC_S_OK) {
            std::string correlationId{ reinterpret_cast<char*>(uuidString) };
            RpcStringFreeA(&uuidString);
            return correlationId;
        }
        return "";
    }
}

namespace Cloudap {
    GUID Aad::AadGlobalIdProviderGuid = { 0xB16898C6, 0xA148, 0x4967, 0x91, 0x71, 0x64, 0xD7, 0x55, 0xDA, 0x85, 0x20 };
    GUID Msa::WLIDProviderGuid = { 0xD7F9888F, 0xE3FC, 0x49b0, 0x9E, 0xA6, 0xA8, 0x5B, 0x5F, 0x39, 0x2A, 0x4F };

    Proxy::Proxy(const std::shared_ptr<Lsa>& lsa)
        : lsa(lsa) {
    }

    bool Proxy::CallPluginGeneric(const GUID* plugin, const std::string& json, void** returnBuffer, size_t* returnBufferLength) const {
        lsa->out << "InputJson: " << json << std::endl;
        size_t requestLength{ sizeof(CALL_PLUGIN_GENERIC_REQUEST) + json.size() + 1 };
        auto request{ reinterpret_cast<CALL_PLUGIN_GENERIC_REQUEST*>(std::malloc(requestLength)) };
        std::memset(request, 0, requestLength);
        request->MessageType = PROTOCOL_MESSAGE_TYPE::CallPluginGeneric;
        std::memcpy(&request->Package, plugin, sizeof(GUID));
        request->BufferLength = json.size() + 1;
        std::memcpy(request->Buffer, json.data(), json.length());
        request->Buffer[json.length()] = '\0';
        if (lsa->Connected()) {
            std::string stringSubmitBuffer(reinterpret_cast<const char*>(request), requestLength);
            *returnBufferLength = 0;
            auto result{ lsa->CallPackage(CLOUDAP_NAME_A, stringSubmitBuffer, returnBuffer, returnBufferLength) };
            if (*returnBufferLength) {
                std::string output{ reinterpret_cast<char*>(*returnBuffer), reinterpret_cast<char*>(*returnBuffer) + *returnBufferLength };
                lsa->out << "OutputJson: " << output << std::endl;
            }
            return result;
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

    bool Proxy::GenARSOPwd(PLUID luid, const std::string& data) const {
        auto requestSize{ sizeof(GEN_ARSO_PASSWORD_REQUEST) + data.length() };
        std::string requestBytes(requestSize, '\0');
        auto request{ reinterpret_cast<PGEN_ARSO_PASSWORD_REQUEST>(requestBytes.data()) };
        request->MessageType = PROTOCOL_MESSAGE_TYPE::GenARSOPwd;
        request->Luid.LowPart = luid->LowPart;
        request->Luid.HighPart = luid->HighPart;
        request->BufferLength = data.length();

        auto ptr{ reinterpret_cast<std::byte*>(request + 1) };
        std::memcpy(ptr, data.data(), data.length());

        void* response;
        auto result{ CallPackage(requestBytes, &response) };
        if (result) {
            LsaFreeReturnBuffer(response);
        }
        return result;
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
        SECPKG_CALL_PACKAGE_TRANSFER_CRED_REQUEST request = { static_cast<ULONG>(PROTOCOL_MESSAGE_TYPE::TransferCreds) };
        request.OriginLogonId.LowPart = sourceLuid->LowPart;
        request.OriginLogonId.HighPart = sourceLuid->HighPart;
        request.DestinationLogonId.LowPart = destinationLuid->LowPart;
        request.DestinationLogonId.HighPart = destinationLuid->HighPart;
        request.Flags = 0; // Ignored by cloudap
        void* response;
        return CallPackage(request, &response);
    }

    bool Proxy::CallPackage(const std::string& submitBuffer, void** returnBuffer) const {
        if (lsa->Connected()) {
            return lsa->CallPackage(CLOUDAP_NAME_A, submitBuffer, returnBuffer);
        }
        return false;
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

    
    bool Proxy::CheckDeviceKeysHealth() const {
        void* returnBuffer{ nullptr };
        size_t returnBufferLength{ 0 };
        auto result = CallPluginGeneric(&AadGlobalIdProviderGuid, "{\"call\":4}", &returnBuffer, &returnBufferLength);
        if (result) {
            LsaFreeReturnBuffer(returnBuffer);
        }
        return result;
    }

    bool Proxy::CreateBindingKey() const {
        void* returnBuffer{ nullptr };
        size_t returnBufferLength{ 0 };
        auto result = CallPluginGeneric(&AadGlobalIdProviderGuid, "{\"call\":12}", &returnBuffer, &returnBufferLength);
        if (result) {
            LsaFreeReturnBuffer(returnBuffer);
        }
        return result;
    }

    bool Proxy::CreateDeviceSSOCookie(const std::string& server, const std::string& nonce) const {
        std::stringstream stream;
        stream << "{\"call\":8,\"payload\":\"https://" << server << "/?sso_nonce=" << nonce << "\", \"correlationId\":\"" << CorrelationId() << "\"}";
        void* returnBuffer{ nullptr };
        size_t returnBufferLength{ 0 };
        auto result = CallPluginGeneric(&AadGlobalIdProviderGuid, stream.str(), &returnBuffer, &returnBufferLength);
        if (result) {
            LsaFreeReturnBuffer(returnBuffer);
        }
        return result;
    }

    bool Proxy::CreateEnterpriseSSOCookie(const std::string& server, const std::string& nonce) const {
        std::stringstream stream;
        stream << "{\"call\":15,\"payload\":\"https://" << server << "/?sso_nonce=" << nonce << "\", \"correlationId\":\"" << CorrelationId() << "\"}";
        void* returnBuffer{ nullptr };
        size_t returnBufferLength{ 0 };
        auto result = CallPluginGeneric(&AadGlobalIdProviderGuid, stream.str(), &returnBuffer, &returnBufferLength);
        if (result) {
            LsaFreeReturnBuffer(returnBuffer);
        }
        return result;
    }

    bool Proxy::CreateNonce() const {
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/74b5513f-08d4-4807-b899-5e03dc9c8d6e
        std::stringstream stream;
        stream << "{\"call\":9,\"correlationId\":\"" << CorrelationId() << "\"}";
        void* returnBuffer{ nullptr };
        size_t returnBufferLength{ 0 };
        auto result = CallPluginGeneric(&AadGlobalIdProviderGuid, stream.str(), &returnBuffer, &returnBufferLength);
        if (result) {
            LsaFreeReturnBuffer(returnBuffer);
        }
        return result;
    }

    bool Proxy::CreateSSOCookie(const std::string& server, const std::string& nonce) const {
        std::stringstream stream;
        stream << "{\"call\":2,\"payload\":\"https://" << server << "/?sso_nonce=" << nonce << "\", \"correlationId\":\"" << CorrelationId() << "\"}";
        void* returnBuffer{ nullptr };
        size_t returnBufferLength{ 0 };
        auto result = CallPluginGeneric(&AadGlobalIdProviderGuid, stream.str(), &returnBuffer, &returnBufferLength);
        if (result) {
            LsaFreeReturnBuffer(returnBuffer);
        }
        return result;
    }

    bool Proxy::DeviceAuth() const {
        std::stringstream stream;
        stream << "{\"call\":5,\"correlationId\":\"" << CorrelationId() << "\"}";
        void* returnBuffer{ nullptr };
        size_t returnBufferLength{ 0 };
        auto result = CallPluginGeneric(&AadGlobalIdProviderGuid, stream.str(), &returnBuffer, &returnBufferLength);
        std::cout << returnBuffer << std::endl;
        return result;
    }

    bool Proxy::DeviceValidityCheck() const {
        std::stringstream stream;
        stream << "{\"call\":7,\"correlationId\":\"" << CorrelationId() << "\"}";
        void* returnBuffer{ nullptr };
        size_t returnBufferLength{ 0 };
        auto result = CallPluginGeneric(&AadGlobalIdProviderGuid, stream.str(), &returnBuffer, &returnBufferLength);
        if (result) {
            LsaFreeReturnBuffer(returnBuffer);
        }
        return result;
    }

    bool Proxy::GenerateBindingClaims() const {
        return false;
    }

    bool Proxy::GetPrtAuthority(AUTHORITY_TYPE authority) const {
        std::stringstream stream;
        stream << "{\"call\":3,\"authoritytype\":" << authority << "}";
        void* returnBuffer{ nullptr };
        size_t returnBufferLength{ 0 };
        auto result{ CallPluginGeneric(&AadGlobalIdProviderGuid, stream.str(), &returnBuffer, &returnBufferLength) };
        if (result) {
            LsaFreeReturnBuffer(returnBuffer);
        }
        return result;
    }

    bool Proxy::RefreshP2PCACert() const {
        void* returnBuffer{ nullptr };
        size_t returnBufferLength{ 0 };
        auto result = CallPluginGeneric(&AadGlobalIdProviderGuid, "{\"call\":6}", &returnBuffer, &returnBufferLength);
        std::cout << returnBuffer << std::endl;
        return result;
    }

    bool Proxy::RefreshP2PCerts() const {
        void* returnBuffer{ nullptr };
        size_t returnBufferLength{ 0 };
        auto result = CallPluginGeneric(&AadGlobalIdProviderGuid, "{\"call\":11}", &returnBuffer, &returnBufferLength);
        std::cout << returnBuffer << std::endl;
        return result;
    }

    bool Proxy::SignPayload() const {
        void* returnBuffer{ nullptr };
        size_t returnBufferLength{ 0 };
        auto result = CallPluginGeneric(&AadGlobalIdProviderGuid, "{\"call\":1}", &returnBuffer, &returnBufferLength);
        std::cout << returnBuffer << std::endl;
        return result;
    }

    bool Proxy::ValidateRdpAssertionRequest(const std::string& authenticationRequest) const {
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/25861219-8546-4780-a9c3-1f709daf4dde
        std::stringstream stream;
        stream << "{\"call\":10,\"payload\":\"" << authenticationRequest << "\",\"correlationId\":\"" << CorrelationId() << "\"}";
        void* returnBuffer{ nullptr };
        size_t returnBufferLength{ 0 };
        auto result{ CallPluginGeneric(&AadGlobalIdProviderGuid, stream.str(), &returnBuffer, &returnBufferLength) };
        if (result) {
            LsaFreeReturnBuffer(returnBuffer);
        }
        return result;
    }
}