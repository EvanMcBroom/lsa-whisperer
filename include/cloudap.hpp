#pragma once
#include <Windows.h>
#include <lsa.hpp>
#include <memory>
#include <string>

#define CLOUDAP_NAME_A "cloudap"

namespace Cloudap {
    // PluginFunctionTable is populated by two other tables,
    // PluginNoNetworkFunctionTable then PluginNetworkOkFunctionTable
    enum class PLUGIN_FUNCTION : ULONG {
        // NoNetwork Functions
        PluginUninitialize = 0,
        ValidateUserInfo,
        GetUnlockKey,
        UnknownFunction3,
        GetDefaultCredentialComplexity,
        IsConnected,
        AcceptPeerCertificate,
        AssembleOpaqueData,
        DisassembleOpaqueData,
        // NetworkOk Functions
        GetToken,
        RefreshToken,
        GetKeys,
        LookupSIDFromIdentityName,
        LookupIdentityFromSIDName,
        UserProfileLoaded,
        ConnectIdentity,
        DisconnectIdentity,
        RenewCertificate,
        GetCertificateFromCred,
        GenericCallPkg,
        PostLogonProcessing
    };

    enum class PROTOCOL_MESSAGE_TYPE : ULONG {
        ReinitPlugin = 0,
        GetTokenBlob,
        CallPluginGeneric,
        ProfileDeleted,
        GetAuthenticatingProvider,
        RenameAccount,
        RefreshTokenBlob,
        GenARSOPwd,
        SetTestParas,
        TransferCreds,
        ProvisionNGCNode,
        GetPwdExpiryInfo,
        DisableOptimizedLogon,
        GetUnlockKeyType,
        GetPublicCachedInfo,
        GetAccountInfo,
        GetDpApiCredKeyDecryptStatus,
        IsCloudToOnPremTgtPresentInCache
    };

    enum class TEST_FLAG : ULONG {
        EnableIdentityCacheFlushes = 1,
        EnablePreRS2Support = 2
    };

    typedef struct _GET_PWD_EXPIRY_INFO_RESPONSE {
        FILETIME ExpiryTime; // When the token blob will expire
        UNICODE_STRING unknown;
    } GET_PWD_EXPIRY_INFO_RESPONSE, *PGET_PWD_EXPIRY_INFO_RESPONSE;

    typedef struct _GET_AUTHENTICATION_PROVIDER_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::GetAuthenticatingProvider };
        LUID Luid{ 0 };
    } GET_AUTHENTICATION_PROVIDER_REQUEST, *PGET_AUTHENTICATION_PROVIDER_REQUEST;

    typedef struct _GET_TOKEN_BLOB_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::GetTokenBlob };
        LUID Luid{ 0 };
    } GET_TOKEN_BLOB_REQUEST, *PGET_TOKEN_BLOB_REQUEST;

    typedef struct _GET_UNLOCK_KEY_TYPE_RESPONSE {
        DWORD Type;
    } GET_UNLOCK_KEY_TYPE_RESPONSE, *PGET_UNLOCK_KEY_TYPE_RESPONSE;

    typedef struct _SET_TEST_PARAS_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::SetTestParas };
        ULONG Flags{ 0 };
    } SET_TEST_PARAS_REQUEST, *PSET_TEST_PARAS_REQUEST;

    typedef struct _TRANSFER_CREDS_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::TransferCreds };
        LUID SourceLuid{ 0 };
        LUID DestinationLuid{ 0 };
    } TRANSFER_CREDS_REQUEST, *PTRANSFER_CREDS_REQUEST;

    class Proxy {
    public:
        Proxy(const std::shared_ptr<Lsa>& lsa);

        // Supported functions in cloudAP!PluginFunctionTable
        bool CallPluginGeneric(GUID* plugin, const std::string& json, void** returnBuffer) const;
        bool DisableOptimizedLogon() const;
        bool GenARSOPwd() const;
        bool GetAccountInfo() const;
        bool GetAuthenticatingProvider(PLUID luid) const;
        bool GetDpApiCredKeyDecryptStatus() const;
        bool GetPublicCachedInfo() const;
        bool GetPwdExpiryInfo(PFILETIME expiryTime, std::string* expiryTimeString) const;
        bool GetTokenBlob(PLUID luid) const;
        bool GetUnlockKeyType() const;
        bool IsCloudToOnPremTgtPresentInCache() const;
        bool ProfileDeleted() const;
        bool ProvisionNGCNode() const;
        bool RefreshTokenBlob() const;
        bool ReinitPlugin() const;
        bool RenameAccount() const;
        bool SetTestParas(ULONG TestFlags) const;
        bool TransferCreds(PLUID sourceLuid, PLUID destinationLuid) const;

    protected:
        std::shared_ptr<Lsa> lsa;

        bool CallPackage(PROTOCOL_MESSAGE_TYPE MessageType) const;
        // You must free all returnBuffer outputs with LsaFreeReturnBuffer
        template<typename _Request, typename _Response>
        bool CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const;
    };

    // The AzureAD plugin (AAD), implemented in aadcloudap.dll
    namespace Aad {
        enum _AUTHORITY_TYPE {
            AUTHORITY_TYPE_1 = 1,
            AUTHORITY_TYPE_2 = 2,
        };

        typedef struct _PRT_INFO {
            LPWSTR unknown1;
            LPWSTR unknown2;
            LPWSTR unknown3;
            LPWSTR unknown4;
            LPWSTR unknown5;
        } PRT_INFO, *PPRT_INFO;

        class Proxy : public Cloudap::Proxy {
        public:
            Proxy(const std::shared_ptr<Lsa>& lsa);

            // Supported functions in aadcloudap!PluginNoNetworkFunctionTable
            void PluginUninitialize() const;
            void ValidateUserInfo() const;
            void GetUnlockKey() const;
            void AcceptPeerCertificate() const;
            void AssembleOpaqueData() const;
            void DisassembleOpaqueData() const;

            // Supported functions in aadcloudap!PluginNetworkOkFunctionTable
            void GetToken() const;
            void RefreshToken() const;
            void GetKeys() const;
            void LookupSIDFromIdentityName() const;
            void LookupIdentityFromSIDName() const;
            void GetCertificateFromCred() const;
            void GenericCallPkg() const;
            void PostLogonProcessing() const;

        private:
            // Requests
            // const BYTE GetPrt[] = "{\"call\":3,\"authoritytype\":1}}"; // From dsreg!PrepareLsaGetPrtRequest
            // const BYTE GetDeviceValidity[] = "{\"call\":7,\"correlationId\":\"%s\"}}"; // From dsreg!PrepareLsaDeviceValidityRequest, %s is a GUID

            // {B16898C6-A148-4967-9171-64D755DA8520}
            const char* AadGlobalIdProviderGuid = "\xC6\x98\x68\xB1\x48\xA1\x67\x49\x91\x71\x64\xD7\x55\xDA\x85\x20";
        };
    }

    // The MicrosoftAccount plugin (MSA), implemented in MicrosoftAccountCloudAP.dll
    namespace Msa {
        class Proxy : public Cloudap::Proxy {
        public:
            Proxy(const std::shared_ptr<Lsa>& lsa);

            // Supported functions in MicrosoftAccountCloudAP!PluginNoNetworkFunctionTable
            void AcceptPeerCertificate() const;
            void GetDefaultCredentialComplexity() const;
            void GetUnlockKey() const;
            void IsConnected() const;
            void PluginUninitialize() const;
            void ValidateUserInfo() const;

            // Supported functions in MicrosoftAccountCloudAP!PluginNetworkOkFunctionTable
            void ConnectIdentity() const;
            void DisconnectIdentity() const;
            void GenericCallPkg() const;
            void GetKeys() const;
            void GetToken() const;
            void RenewCertificate() const;
            void UserProfileLoaded() const;

        private:
            // {D7F9888F-E3FC-49b0-9EA6-A85B5F392A4F}
            const char* WLIDProviderGuid = "\x8F\x88\xF9\xD7\xFC\xE3\xB0\x49\x9E\xA6\xA8\x5B\x5F\x39\x2A\x4F";
        };
    }
}