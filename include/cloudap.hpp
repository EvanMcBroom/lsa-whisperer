#pragma once
#include <pch.hpp>

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

    typedef struct _DISABLE_OPTIMIZED_LOGON_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::DisableOptimizedLogon };
        LUID Luid{ 0 };
    } DISABLE_OPTIMIZED_LOGON_REQUEST, *PDISABLE_OPTIMIZED_LOGON_REQUEST;

    typedef struct _GEN_ARSO_PASSWORD_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::GenARSOPwd };
        LUID Luid{ 0 };
        ULONG BufferLength;
        CHAR Buffer[0];
    } GEN_ARSO_PASSWORD_REQUEST, *PGEN_ARSO_PASSWORD_REQUEST;

    typedef struct _GET_ACCOUNT_INFO_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::GenARSOPwd };
        GUID PackageGuid{ 0 };
        PSID Sid;
        // Pad of 0x3C
    } GET_ACCOUNT_INFO_REQUEST, *PGET_ACCOUNT_INFO_REQUEST;

    typedef struct _GET_AUTHENTICATION_PROVIDER_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::GetAuthenticatingProvider };
        LUID Luid{ 0 };
    } GET_AUTHENTICATION_PROVIDER_REQUEST, *PGET_AUTHENTICATION_PROVIDER_REQUEST;

    typedef struct _GET_AUTHENTICATION_PROVIDER_RESPONSE {
        GUID provider;
    } GET_AUTHENTICATION_PROVIDER_RESPONSE, *PGET_AUTHENTICATION_PROVIDER_RESPONSE;
    
    typedef struct _GET_DP_API_CRED_KEY_DECRYPT_STATUS_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::GetDpApiCredKeyDecryptStatus };
        LUID Luid{ 0 };
    } GET_DP_API_CRED_KEY_DECRYPT_STATUS_REQUEST, *PGET_DP_API_CRED_KEY_DECRYPT_STATUS_REQUEST;

    typedef struct _GET_DP_API_CRED_KEY_DECRYPT_STATUS_RESPONSE {
        DWORD IsDecrypted;
    } GET_DP_API_CRED_KEY_DECRYPT_STATUS_RESPONSE, *PGET_DP_API_CRED_KEY_DECRYPT_STATUS_RESPONSE;

    typedef struct _GET_PUBLIC_CACHED_INFO_REQUEST { // wip
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::GenARSOPwd };
        GUID PackageGuid{ 0 };
        ULONG StringLength{ 6 }; // Length must be 6
        ULONG StringMaximumLength;
        PWSTR StringBuffer;
    } GET_PUBLIC_CACHED_INFO_REQUEST, *PGET_PUBLIC_CACHED_INFO_REQUEST;

    typedef struct _GET_PWD_EXPIRY_INFO_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::GetPwdExpiryInfo };
        LUID Luid{ 0 };
    } GET_PWD_EXPIRY_INFO_REQUEST, *PGET_PWD_EXPIRY_INFO_REQUEST;

    typedef struct _GET_PWD_EXPIRY_INFO_RESPONSE {
        LPVOID ExpiryTime; // When the token blob will expire
        UNICODE_STRING ExpiryString;
    } GET_PWD_EXPIRY_INFO_RESPONSE, *PGET_PWD_EXPIRY_INFO_RESPONSE;

    typedef struct _GET_TOKEN_BLOB_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::GetTokenBlob };
        LUID Luid{ 0 };
    } GET_TOKEN_BLOB_REQUEST, *PGET_TOKEN_BLOB_REQUEST;

    typedef struct _GET_UNLOCK_KEY_TYPE_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::GetUnlockKeyType };
        LUID Luid{ 0 };
    } GET_UNLOCK_KEY_TYPE_REQUEST, *PGET_UNLOCK_KEY_TYPE_REQUEST;

    typedef struct _GET_UNLOCK_KEY_TYPE_RESPONSE {
        DWORD Type;
    } GET_UNLOCK_KEY_TYPE_RESPONSE, *PGET_UNLOCK_KEY_TYPE_RESPONSE;

    typedef struct _IS_CLOUD_TO_ON_PREM_TGT_PRESENT_IN_CACHE_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::IsCloudToOnPremTgtPresentInCache };
        LUID Luid{ 0 };
    } IS_CLOUD_TO_ON_PREM_TGT_PRESENT_IN_CACHE_REQUEST, *PIS_CLOUD_TO_ON_PREM_TGT_PRESENT_IN_CACHE_REQUEST;

    typedef struct _IS_CLOUD_TO_ON_PREM_TGT_PRESENT_IN_CACHE_RESPONSE {
        DWORD IsPresent;
    } IS_CLOUD_TO_ON_PREM_TGT_PRESENT_IN_CACHE_RESPONSE, *PIS_CLOUD_TO_ON_PREM_TGT_PRESENT_IN_CACHE_RESPONSE;

    typedef struct _PROFILE_DELETED_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::ProfileDeleted };
        ULONG SidOffset; // Offset to PSID pointer within structure
        ULONG SidLength;
        ULONG SidMaximumLength;
        PSID Sid;
    } PROFILE_DELETED_REQUEST, *PPROFILE_DELETED_REQUEST;

    typedef struct _SET_TEST_PARAS_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::SetTestParas };
        ULONG Flags{ 0 };
    } SET_TEST_PARAS_REQUEST, *PSET_TEST_PARAS_REQUEST;

    typedef struct _TRANSFER_CRED_REQUEST : _SECPKG_CALL_PACKAGE_TRANSFER_CRED_REQUEST {
        _TRANSFER_CRED_REQUEST() {
            MessageType = static_cast<ULONG>(PROTOCOL_MESSAGE_TYPE::TransferCreds);
            Flags = 0; // must be 0
        }
    } TRANSFER_CRED_REQUEST, *PTRANSFER_CRED_REQUEST;

    class Proxy {
    public:
        Proxy(const std::shared_ptr<Lsa>& lsa);

        // Supported functions in cloudAP!PluginFunctionTable
        bool CallPluginGeneric(GUID* plugin, const std::string& json, void** returnBuffer) const;
        bool DisableOptimizedLogon(PLUID luid) const;
        bool GenARSOPwd() const;
        bool GetAccountInfo() const;
        bool GetAuthenticatingProvider(PLUID luid) const;
        bool GetDpApiCredKeyDecryptStatus(PLUID luid) const;
        bool GetPublicCachedInfo() const;
        bool GetPwdExpiryInfo(PLUID luid) const;
        bool GetTokenBlob(PLUID luid) const;
        bool GetUnlockKeyType(PLUID luid) const;
        bool IsCloudToOnPremTgtPresentInCache(PLUID luid) const;
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

        template<typename _Request, typename _Response>
        bool CallPackage(const _Request& submitBuffer, _Response** returnBuffer, size_t* returnBufferLength) const;
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