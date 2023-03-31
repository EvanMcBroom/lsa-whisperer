#include <Windows.h>
#include <cloudap.hpp>
#include <iostream>
#include <lsa.hpp>

namespace Cloudap {
    Proxy::Proxy(const std::shared_ptr<Lsa>& lsa)
        : lsa(lsa) {
    }

    bool Proxy::CallPluginGeneric(GUID* plugin, const std::string& json, void** returnBuffer) const {
        return false;
    }

    bool Proxy::DisableOptimizedLogon() const {
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::DisableOptimizedLogon);
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
        void* response;
        return this->CallPackage(request, &response);
    }

    bool Proxy::GetDpApiCredKeyDecryptStatus() const {
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::GetDpApiCredKeyDecryptStatus);
    }

    bool Proxy::GetPublicCachedInfo() const {
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::GetPublicCachedInfo);
    }

    bool Proxy::GetPwdExpiryInfo(PFILETIME expiryTime, std::string* expiryTimeString) const {
        auto request{ PROTOCOL_MESSAGE_TYPE::GetPwdExpiryInfo };
        void* response{ nullptr };
        auto status{ CallPackage(request, &response) };
        return status;
    }

    bool Proxy::GetTokenBlob(PLUID luid) const {
        GET_TOKEN_BLOB_REQUEST request;
        request.Luid.LowPart = luid->LowPart;
        request.Luid.HighPart = luid->HighPart;
        void* response;
        return CallPackage(request, &response);
    }

    bool Proxy::GetUnlockKeyType() const {
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::GetUnlockKeyType);
    }

    bool Proxy::IsCloudToOnPremTgtPresentInCache() const {
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::IsCloudToOnPremTgtPresentInCache);
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
        TRANSFER_CREDS_REQUEST request;
        request.SourceLuid.LowPart = sourceLuid->LowPart;
        request.SourceLuid.HighPart = sourceLuid->HighPart;
        request.DestinationLuid.LowPart = destinationLuid->LowPart;
        request.DestinationLuid.HighPart = destinationLuid->HighPart;
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
        if (lsa->Connected()) {
            std::string stringSubmitBuffer(reinterpret_cast<const char*>(&submitBuffer), sizeof(decltype(submitBuffer)));
            return lsa->CallPackage(CLOUDAP_NAME_A, stringSubmitBuffer, reinterpret_cast<void**>(returnBuffer));
        }
        return false;
    }
}