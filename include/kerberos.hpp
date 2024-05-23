#pragma once
#include <pch.hpp>

#include <lsa.hpp>
#include <memory>
#include <string>
#include <vector>

namespace Kerberos {
    enum class CacheOptions : ULONG {
        Default = 0x0,
        DontUseCache = 0x1,
        UseCacheOnly = 0x2,
        UseCredhandle = 0x4,
        // NT 5.1
        AsKerbCred = 0x8,
        WithSecCred = 0x10,
        // NT 6.0
        CACHE_TICKET = 0x20,
        // NT 6.1
        MAX_LIFETIME = 0x40
    };

    // Defined here for reference. Originally defined in DsGetDC.h
    enum class DcFlags : ULONG {
        Pdc = 0x00000001, // DC is PDC of Domain
        Gc = 0x00000004, // DC is a GC of forest
        Ldap = 0x00000008, // Server supports an LDAP server
        Ds = 0x00000010, // DC supports a DS and is a Domain Controller
        Kdc = 0x00000020, // DC is running KDC service
        Timeserv = 0x00000040, // DC is running time service
        Closest = 0x00000080, // DC is in closest site to client
        Writable = 0x00000100, // DC has a writable DS
        GoodTimeserv = 0x00000200, // DC is running time service (and has clock hardware)
        Ndnc = 0x00000400, // DomainName is non-domain NC serviced by the LDAP server
        SelectSecretDomain6 = 0x00000800, // DC has some secrets
        FullSecretDomain6 = 0x00001000, // DC has all secrets
        Ws = 0x00002000, // DC is running web service
        Ds8 = 0x00004000, // DC is running Win8 or later
        Ds9 = 0x00008000, // DC is running Win8.1 or later
        Ds10 = 0x00010000, // DC is running WinThreshold or later
        KeyList = 0x00020000, // DC supports key list requests
        Pings = 0x000FFFFF, // Flags returned on ping
        DnsController = 0x20000000, // DomainControllerName is a DNS name
        DnsDomain = 0x40000000, // DomainName is a DNS name
        DnsForest = 0x80000000 // DnsForestName is a DNS name
    };

    enum class EncryptionType {
        Null = 0,
        DesCbcCrc = 1,
        DesCbcMd4 = 2,
        DesCbcMd5 = 3,
        Aes128CtsHmacSha1_96 = 17,
        Aes256CtsHmacSha1_96 = 18,
        Rc4Md4 = -128,
        Rc4Plain2 = -129,
        Rc4Lm = -130,
        Rc4sha = -131,
        DesPlan = -132,
        Rc4HmacOld = -133,
        Rc4PlainOld = -134,
        Rc4HmacOldExp = -135,
        Rc4PlainOldExp = -136,
        Rc4Plain = -140,
        Rc4PlainExp = -141
    };

    enum class ExtendedPolicies {
        None = 0,
        DacDisabled = 1
    };

    enum class PROTOCOL_MESSAGE_TYPE : ULONG {
        DebugRequest = 0,
        QueryTicketCache,
        ChangeMachinePassword,
        VerifyPac,
        RetrieveTicket,
        UpdateAddresses,
        PurgeTicketCache,
        ChangePassword,
        RetrieveEncodedTicket,
        DecryptData,
        AddBindingCacheEntry,
        SetPassword,
        SetPasswordEx,
        VerifyCredentials,
        QueryTicketCacheEx,
        PurgeTicketCacheEx,
        RefreshSmartcardCredentials,
        AddExtraCredentials,
        QuerySupplementalCredentials,
        TransferCredentials,
        QueryTicketCacheEx2,
        SubmitTicket,
        AddExtraCredentialsEx,
        QueryKdcProxyCache,
        PurgeKdcProxyCache,
        QueryTicketCacheEx3,
        CleanupMachinePkinitCreds,
        AddBindingCacheEntryEx,
        QueryBindingCache,
        PurgeBindingCache,
        PinKdc,
        UnpinAllKdcs,
        QueryDomainExtendedPolicies,
        QueryS4U2ProxyCache,
        RetrieveKeyTab,
        RefreshPolicy,
        PrintCloudKerberosDebug,
        NetworkTicketLogon,
        NlChangeMachinePassword
    };

    enum class TicketFlags : ULONG {
        None = 0,
        Reserved1 = 0x00000001,
        NameCanonicalize = 0x00010000,
        EncPaRep = 0x00010000,
        CNameInPaData = 0x00040000, // Only valid on NT 5.1
        OkAsDelegate = 0x00040000,
        HwAuthent = 0x00100000,
        PreAuthent = 0x00200000,
        Initial = 0x00400000,
        Renewable = 0x00800000,
        Invalid = 0x01000000,
        PostDated = 0x02000000,
        MayPostdate = 0x04000000,
        Proxy = 0x08000000,
        Proxiable = 0x10000000,
        Forwarded = 0x20000000,
        Forwardable = 0x40000000,
        Feserved = 0x80000000
    };

    // Required structure for call KerbChangeMachinePasswordMessage
    typedef struct _CHANGE_MACH_PWD_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::ChangeMachinePassword };
        UNICODE_STRING NewPassword;
        UNICODE_STRING OldPassword;
    } CHANGE_MACH_PWD_REQUEST, * PCHANGE_MACH_PWD_REQUEST;

    // Temporarily added until GitHub's "windows-latest" runner includes Windows11 SDK 26100
    // Required structure for call NlChangeMachinePassword
    typedef struct _CHANGEMACHINEPASSWORD_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::NlChangeMachinePassword };
        BOOLEAN Impersonating;
    } CHANGEMACHINEPASSWORD_REQUEST, *PCHANGEMACHINEPASSWORD_REQUEST;

    class Proxy {
    public:
        Proxy(const std::shared_ptr<Lsa>& lsa);

        // A subset of the supported functions in Kerberos
        bool AddBindingCacheEntry(const std::wstring& realmName, const std::wstring& kdcAddress, ULONG addressType) const;
        bool AddBindingCacheEntryEx(const std::wstring& realmName, const std::wstring& kdcAddress, ULONG addressType, ULONG dcFlags, bool useEx = true) const;
        bool AddExtraCredentials(PLUID luid, const std::wstring& domainName, const std::wstring& userName, const std::wstring& password, ULONG flags) const;
        bool CleanupMachinePkinitCreds(PLUID luid) const;
        bool NlChangeMachinePassword(bool impersonating) const;
        bool PinKdc(const std::wstring& domainName, const std::wstring& dcName, ULONG dcFlags) const;
        bool PrintCloudKerberosDebug(PLUID luid) const;
        bool PurgeBindingCache() const;
        bool PurgeKdcProxyCache(PLUID luid) const;
        bool PurgeTicketCache(PLUID luid, const std::wstring& serverName, const std::wstring& serverRealm) const;
        bool PurgeTicketCacheEx(PLUID luid, ULONG flags, const std::wstring& clientName, const std::wstring& clientRealm, const std::wstring& serverName, const std::wstring& serverRealm) const;
        bool QueryBindingCache() const;
        bool QueryDomainExtendedPolicies(const std::wstring& domainName) const;
        bool QueryKdcProxyCache(PLUID luid) const;
        bool QueryS4U2ProxyCache(PLUID luid) const;
        bool QueryTicketCache(PLUID luid) const;
        bool QueryTicketCacheEx(PLUID luid) const;
        bool QueryTicketCacheEx2(PLUID lRetrieveTicketuid) const;
        bool QueryTicketCacheEx3(PLUID luid) const;
        bool RetrieveTicket(PLUID luid, const std::wstring& targetName, TicketFlags flags = TicketFlags::None, CacheOptions options = CacheOptions::AsKerbCred, EncryptionType type = EncryptionType::Null, bool encoded = false) const;
        bool RetrieveEncodedTicket(PLUID luid, const std::wstring& targetName, TicketFlags flags = TicketFlags::None, CacheOptions options = CacheOptions::AsKerbCred, EncryptionType type = EncryptionType::Null) const;
        bool RetrieveKeyTab(const std::wstring& domainName, const std::wstring& userName, const std::wstring& password) const;
        bool TransferCreds(PLUID sourceLuid, PLUID destinationLuid, ULONG flags) const; // Flags may be CleanupCredentials or OptimisticLogon
        bool UnpinAllKdcs() const;

    protected:
        std::shared_ptr<Lsa> lsa;

    private:
        // You must free all returnBuffer outputs with LsaFreeReturnBuffer
        bool CallPackage(const std::string& submitBuffer, void** returnBuffer) const;

        template<typename _Request, typename _Response>
        bool CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const;

        template<typename _Request, typename _Response>
        bool CallPackage(_Request* submitBuffer, size_t submitBufferLength, _Response** returnBuffer) const;
    };
}