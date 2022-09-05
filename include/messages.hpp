#pragma once
#include <Windows.h>
#define _NTDEF_ // Required to include both Ntsecapi and Winternl
#include <Ntsecapi.h>

#pragma pack(show) // normally 16
#ifdef _WIN64
    #pragma pack(push, 8)
#else
    #pragma pack(push, 4)
#endif
#pragma pack(show)

namespace MSV1_0 {
    enum class CacheLogonFlags : ULONG {
        RequestMitLogon = 1,
        RequestInfo4 = 2,
        DeleteEntry = 4,
        RequestSmartcardOnly = 8
    };

    enum class CacheLookupCredType : ULONG {
        None = 0,
        Raw, // Used for public-key smart card data
        Ntowf
    };

    enum class DeriveCredType : ULONG {
        Sha1 = 0,
        Sha1V2
    };

    enum class ProcessOption : ULONG {
        AllowBlankPassword = 0x01,
        DisableAdminLockout = 0x02,
        DisableForceGuest = 0x04,
        AllowOldPassword = 0x08,
        TryCacheFirst = 0x10
    };

    // Redefine MSV1_0_PROTOCOL_MESSAGE_TYPE to ensure all members are included
    enum class PROTOCOL_MESSAGE_TYPE : ULONG {
        Lm20ChallengeRequest = 0,
        Lm20GetChallengeResponse,
        EnumerateUsers,
        GetUserInfo,
        ReLogonUsers,
        ChangePassword,
        ChangeCachedPassword,
        GenericPassthrough,
        CacheLogon,
        SubAuth,
        DeriveCredential,
        CacheLookup,
        SetProcessOption,
        ConfigLocalAliases,
        ClearCachedCredentials,
        LookupToken,
        ValidateAuth,
        CacheLookupEx,
        GetCredentialKey,
        SetThreadOption,
        DecryptDpapiMasterKey,
        GetStrongCredentialKey,
        TransferCred,
        ProvisionTbal,
        DeleteTbalSecrets
    };

    typedef struct _CACHE_LOGON_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::CacheLogon };
        PVOID LogonInformation;
        PVOID ValidationInformation;
        PVOID SupplementalCacheData;
        ULONG SupplementalCacheDataLength;
        ULONG RequestFlags{ 0 };
    } CACHE_LOGON_REQUEST, * PCACHE_LOGON_REQUEST;

    typedef struct _CACHE_LOOKUP_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::CacheLookup };
        UNICODE_STRING UserName;
        UNICODE_STRING DomainName;
        CacheLookupCredType CredentialType;
        ULONG CredentialInfoLength;
        UCHAR CredentialSubmitBuffer[1]; // in-place array of length CredentialInfoLength
    } CACHE_LOOKUP_REQUEST, * PCACHE_LOOKUP_REQUEST;

    typedef struct _CACHE_LOOKUP_RESPONSE {
        PROTOCOL_MESSAGE_TYPE MessageType;
        PVOID ValidationInformation;
        PVOID SupplementalCacheData;
        ULONG SupplementalCacheDataLength;
    } CACHE_LOOKUP_RESPONSE, * PCACHE_LOOKUP_RESPONSE;

    typedef struct _CACHE_LOOKUP_EX_REQUEST : public CACHE_LOOKUP_REQUEST {
        _CACHE_LOOKUP_EX_REQUEST() {
            this->MessageType = PROTOCOL_MESSAGE_TYPE::CacheLookupEx;
        }
    } CACHE_LOOKUP_EX_REQUEST, * PCACHE_LOOKUP_EX_REQUEST;

    typedef struct _CACHE_LOOKUP_EX_RESPONSE : CACHE_LOOKUP_RESPONSE {
    } CACHE_LOOKUP_EX_RESPONSE, * PCACHE_LOOKUP_EX_RESPONSE;

    typedef struct _CHANGE_PASSWORD_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::ChangePassword };
        UNICODE_STRING DomainName;
        UNICODE_STRING AccountName;
        UNICODE_STRING OldPassword;
        UNICODE_STRING NewPassword;
        BOOLEAN Impersonating;
    } CHANGE_PASSWORD_REQUEST, * PCHANGE_PASSWORD_REQUEST;

    typedef struct _CHANGE_PASSWORD_RESPONSE {
        PROTOCOL_MESSAGE_TYPE MessageType;
        BOOLEAN PasswordInfoValid;
        DOMAIN_PASSWORD_INFORMATION DomainPasswordInfo;
    } CHANGE_PASSWORD_RESPONSE, * PCHANGE_PASSWORD_RESPONSE;

    typedef struct _CHANGE_CACHED_PASSWORD_REQUEST : public CHANGE_PASSWORD_REQUEST {
        _CHANGE_CACHED_PASSWORD_REQUEST() {
            this->MessageType = PROTOCOL_MESSAGE_TYPE::ChangeCachedPassword;
        }
    } CHANGE_CACHED_PASSWORD_REQUEST, * PCHANGE_CACHED_PASSWORD_REQUEST;

    typedef struct _CHANGE_CACHED_PASSWORD_RESPONSE : CHANGE_PASSWORD_RESPONSE {
    } CHANGE_CACHED_PASSWORD_RESPONSE, * PCHANGE_CACHED_PASSWORD_RESPONSE;

    typedef struct _CLEAR_CACHED_CREDENTIALS_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::ClearCachedCredentials };
    } CLEAR_CACHED_CREDENTIALS_REQUEST, * PCLEAR_CACHED_CREDENTIALS_REQUEST;

    typedef struct _DECRYPT_DPAPI_MASTER_KEY_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::DecryptDpapiMasterKey };
        DWORD unknown2;
        LUID unknown3;
        DWORD unknown4;
    } DECRYPT_DPAPI_MASTER_KEY_REQUEST, * PDECRYPT_DPAPI_MASTER_KEY_REQUEST;

    typedef struct _DECRYPT_DPAPI_MASTER_KEY_RESPONSE {
        PROTOCOL_MESSAGE_TYPE MessageType;
        // ...
    } DECRYPT_DPAPI_MASTER_KEY_RESPONSE, * PDECRYPT_DPAPI_MASTER_KEY_RESPONSE;

    typedef struct _DELETE_TBAL_SECRETS_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::DeleteTbalSecrets };
    } DELETE_TBAL_SECRETS_REQUEST, * PDELETE_TBAL_SECRETS_REQUEST;

    typedef struct _DERIVECRED_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::DeriveCredential };
        LUID LogonId;
        ULONG DeriveCredType;
        ULONG DeriveCredInfoLength;
        UCHAR DeriveCredSubmitBuffer[1];
    } DERIVECRED_REQUEST, * PDERIVECRED_REQUEST;

    typedef struct _DERIVECRED_RESPONSE {
        MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
        ULONG DeriveCredInfoLength;
        UCHAR DeriveCredReturnBuffer[1];
    } DERIVECRED_RESPONSE, * PDERIVECRED_RESPONSE;

    typedef struct _ENUMUSERS_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::EnumerateUsers };
    } ENUMUSERS_REQUEST, * PENUMUSERS_REQUEST;

    typedef struct _ENUMUSERS_RESPONSE {
        PROTOCOL_MESSAGE_TYPE MessageType;
        ULONG NumberOfLoggedOnUsers;
        PLUID LogonIds;
        PULONG EnumHandles;
    } ENUMUSERS_RESPONSE, * PENUMUSERS_RESPONSE;

    typedef struct _GET_CREDENTIAL_KEY_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::GetCredentialKey };
        LUID LogonId;
    } GET_CREDENTIAL_KEY_REQUEST, * PGET_CREDENTIAL_KEY_REQUEST;

    typedef struct _GET_CREDENTIAL_KEY_RESPONSE {
        PROTOCOL_MESSAGE_TYPE MessageType;
        // ...
    } GET_CREDENTIAL_KEY_RESPONSE, * PGET_CREDENTIAL_KEY_RESPONSE;

    typedef struct _GETUSERINFO_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::GetUserInfo  };
        LUID LogonId;
    } GETUSERINFO_REQUEST, * PGETUSERINFO_REQUEST;

    typedef struct _GETUSERINFO_RESPONSE {
        PROTOCOL_MESSAGE_TYPE MessageType;
        PSID UserSid;
        UNICODE_STRING UserName;
        UNICODE_STRING LogonDomainName;
        UNICODE_STRING LogonServer;
        SECURITY_LOGON_TYPE LogonType;
    } GETUSERINFO_RESPONSE, * PGETUSERINFO_RESPONSE;

    typedef struct _GET_STRONG_CREDENTIAL_KEY_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::GetStrongCredentialKey };
        DWORD unknown1; // 0X04
        LUID unknown2; // 0x28
        DWORD unknown3; // 0x30
        DWORD unknown4; // 0x34
        DWORD unknown5; // 0x38
        DWORD unknown6; // 0x40
        GUID unknown7; // 0x48
    } GET_STRONG_CREDENTIAL_KEY_REQUEST, * PGET_STRONG_CREDENTIAL_KEY_REQUEST;

    typedef struct _GET_STRONG_CREDENTIAL_KEY_RESPONSE {
        PROTOCOL_MESSAGE_TYPE MessageType;
        // ...
    } GET_STRONG_CREDENTIAL_KEY_RESPONSE, * PGET_STRONG_CREDENTIAL_KEY_RESPONSE;

    typedef struct _PASSTHROUGH_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::GenericPassthrough };
        UNICODE_STRING DomainName;
        UNICODE_STRING PackageName;
        ULONG DataLength;
        PUCHAR LogonData;
        ULONG Pad{ 0 };
    } PASSTHROUGH_REQUEST, * PPASSTHROUGH_REQUEST;

    typedef struct _PASSTHROUGH_RESPONSE {
        PROTOCOL_MESSAGE_TYPE MessageType;
        ULONG Pad{ 0 };
        ULONG DataLength;
        PUCHAR ValidationData;
    } PASSTHROUGH_RESPONSE, * PPASSTHROUGH_RESPONSE;

    typedef struct _PROVISION_TBAL_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::ProvisionTbal };
        LUID LogonId;
    } PROVISION_TBAL_REQUEST, * PPROVISION_TBAL_REQUEST;

    typedef struct _SETPROCESSOPTION_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::SetProcessOption };
        ULONG ProcessOptions{ 0 };
        BOOLEAN DisableOptions;
    } SETPROCESSOPTION_REQUEST, * PSETPROCESSOPTION_REQUEST;

    typedef struct _TRANSFER_CRED_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::TransferCred };
        DWORD LUID;
        DWORD unknown2;
        DWORD unknown3;
        DWORD unknown4;
    } TRANSFER_CRED_REQUEST, * PTRANSFER_CRED_REQUEST;

    typedef struct _TRANSFER_CRED_RESPONSE {
        PROTOCOL_MESSAGE_TYPE MessageType;
        // ...
    } TRANSFER_CRED_RESPONSE, * PTRANSFER_CRED_RESPONSE;
}

#pragma pack(pop)