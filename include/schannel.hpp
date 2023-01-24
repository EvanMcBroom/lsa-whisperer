#pragma once
#include <Winternl.h>
#include <cxxopts.hpp>
#include <lsa.hpp>

namespace Schannel {
    //enum class CacheFlag : ULONG {
    //    Empty = 1,
    //    Readonly = 2,
    //    MasterEphem = 4,
    //    UseValidated = 0x10,
    //};

    enum class PurgeEntriesType : ULONG {
        Client = 1,
        Server = 2,
        // Originally included in Windows for testing
        ClientAll = 0x00010000,
        ServerAll = 0x00010000,
        ServerEntriesDisardLocators = 0x00040000
    };

    enum class RetrieveEntriesType : ULONG {
        Client = 1,
        Server = 2,
    };

    enum class PROTOCOL_MESSAGE_TYPE : ULONG {
        LookupCert = 2,
        PurgeCache,
        CacheInfo,
        PerfmonInfo,
        LookupExternalCert,
        StreamSizes = 8,
    };

    typedef struct _CERT_NAME_INFO {
        ULONG IssuerOffset; // ASN1 encoded
        ULONG IssuerLength;
    } CERT_NAME_INFO, * PCERT_NAME_INFO;

    typedef struct _CERT_LOGON_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::LookupCert };
        ULONG Length;
        ULONG OffsetCertificate;
        ULONG CertLength;
        ULONG Flags;
        ULONG CertCount;
        CERT_NAME_INFO NameInfo[1];
    } CERT_LOGON_REQUEST, * PCERT_LOGON_REQUEST;

    typedef struct _CERT_LOGON_RESPONSE {
        ULONG MessageType;
        ULONG Length;
        ULONG OffsetAuthData;
        ULONG AuthDataLength;
        ULONG Flags;
        ULONG OffsetDomain;
        ULONG DomainLength;
        ULONG Align;
    } CERT_LOGON_RESPONSE, * PCERT_LOGON_RESPONSE;

    typedef struct _EXTERNAL_CERT_LOGON_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::LookupExternalCert };
        ULONG Length;
        ULONG CredentialType;
        PVOID Credential;
        ULONG Flags;
    } EXTERNAL_CERT_LOGON_REQUEST, * PEXTERNAL_CERT_LOGON_REQUEST;

    typedef struct _EXTERNAL_CERT_LOGON_RESPONSE {
        PROTOCOL_MESSAGE_TYPE MessageType;
        ULONG Length;
        HANDLE UserToken;
        ULONG Flags;
    } EXTERNAL_CERT_LOGON_RESPONSE, * PEXTERNAL_CERT_LOGON_RESPONSE;

    typedef struct _PERFMON_INFO_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::PerfmonInfo };
        DWORD Flags;
    } PERFMON_INFO_REQUEST, * PPERFMON_INFO_REQUEST;

    typedef struct _PERFMON_INFO_RESPONSE {
        DWORD ClientCacheEntries;
        DWORD ServerCacheEntries;
        DWORD ClientActiveEntries;
        DWORD ServerActiveEntries;
        DWORD ClientHandshakesPerSecond;
        DWORD ServerHandshakesPerSecond;
        DWORD ClientReconnectsPerSecond;
        DWORD ServerReconnectsPerSecond;
    } PERFMON_INFO_RESPONSE, * PPERFMON_INFO_RESPONSE;

    typedef struct _PURGE_SESSION_CACHE_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::PurgeCache };
        LUID LogonId;
        UNICODE_STRING ServerName;
        DWORD Flags;
    } PURGE_SESSION_CACHE_REQUEST, * PPURGE_SESSION_CACHE_REQUEST;

    typedef struct _SESSION_CACHE_INFO_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::CacheInfo };
        LUID LogonId;
        UNICODE_STRING ServerName;
        DWORD Flags;
    } SESSION_CACHE_INFO_REQUEST, * PSESSION_CACHE_INFO_REQUEST;

    typedef struct _SESSION_CACHE_INFO_RESPONSE {
        DWORD CacheSize;
        DWORD Entries;
        DWORD ActiveEntries;
        DWORD Zombies;
        DWORD ExpiredZombies;
        DWORD AbortedZombies;
        DWORD DeletedZombies;
    } SESSION_CACHE_INFO_RESPONSE, * PSESSION_CACHE_INFO_RESPONSE;


    typedef struct _STREAM_SIZES_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::StreamSizes };
    } STREAM_SIZES_REQUEST, * PSTREAM_SIZES_REQUEST;

    typedef struct _STREAM_SIZES_RESPONSE {
        PROTOCOL_MESSAGE_TYPE MessageType;
        DWORD unknown[3];
    } STREAM_SIZES_RESPONSE, * PSTREAM_SIZES_RESPONSE;
    
    class Proxy : public Sspi {
    public:
        // A subset of the supported functions in pku2u
        bool CacheInfo(PLUID logonId, const std::wstring& serverName, ULONG flags) const;
        bool LookupCert(const std::vector<byte>& certificate, ULONG flags, std::vector<std::vector<byte>> issuers) const;
        bool LookupExternalCert(ULONG type, const std::vector<byte>& credential, ULONG flags) const;
        bool PerfmonInfo(ULONG flags) const;
        bool PurgeCache(PLUID logonId, const std::wstring& serverName, ULONG flags) const;
        bool StreamSizes() const;

    private:
        // You must free all returnBuffer outputs with LsaFreeReturnBuffer
        template<typename _Request, typename _Response>
        bool CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const;
    };
    
	bool HandleFunction(std::ostream& out, const Proxy& proxy, const std::string& function, const cxxopts::ParseResult& options);
	void Parse(std::ostream& out, const std::vector<std::string>& args);
}