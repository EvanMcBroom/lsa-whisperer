#define _NTDEF_ // Required to include both Ntsecapi and Winternl
#include <Winternl.h>
#include <iostream>
#include <lsa.hpp>
#include <string>
#include <vector>
#include <schannel.h>
#include <schannel/messages.hpp>

#define STATUS_SUCCESS 0

namespace Schannel {
    template<typename _Request, typename _Response>
    bool CallPackage(const _Request& submitBuffer, _Response** returnBuffer) {
        std::string stringSubmitBuffer(reinterpret_cast<const char*>(&submitBuffer), sizeof(decltype(submitBuffer)));
        return ::CallPackage(UNISP_NAME_A, stringSubmitBuffer, reinterpret_cast<void**>(returnBuffer));
    }

    bool CacheInfo(PLUID logonId, const std::wstring& serverName, ULONG flags) {
        SESSION_CACHE_INFO_REQUEST request;
        request.LogonId.LowPart = logonId->LowPart;
        request.LogonId.HighPart = logonId->HighPart;
        UnicodeString serverNameGuard{ serverName };
        request.ServerName = serverNameGuard;
        request.Flags = flags;
        void* response;
        return CallPackage(request, &response);
    }

    bool LookupCert(const std::vector<byte>& certificate, ULONG flags, std::vector<std::vector<byte>> issuers) {
        //CERT_LOGON_REQUEST request;
        //request.LogonInformation = logonInfo;
        //request.ValidationInformation = validationInfo;
        //request.SupplementalCacheData = const_cast<byte*>(supplementalCacheData.data());
        //request.SupplementalCacheDataLength = supplementalCacheData.size();
        //void* response;
        //return CallPackage(request, &response);
        return false;
    }

    bool LookupExternalCert(ULONG type, const std::vector<byte>& credential, ULONG flags) {
        EXTERNAL_CERT_LOGON_REQUEST request;
        request.Length = 0; // ?
        request.CredentialType = type;
        request.Credential = nullptr; // ?
        request.Flags = flags;
        EXTERNAL_CERT_LOGON_RESPONSE* response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            std::cout << "Length   : " << response->Length << std::endl;
            std::cout << "UserToken: " << response->UserToken << std::endl;
            std::cout << "Flags    : " << response->Flags << std::endl;
        }
        return result;
    }

    bool PerfmonInfo(ULONG flags) {
        PERFMON_INFO_REQUEST request;
        request.Flags = flags;
        PERFMON_INFO_RESPONSE* response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            std::cout << "ClientCacheEntries       : " << response->ClientCacheEntries << std::endl;
            std::cout << "ServerCacheEntries       : " << response->ServerCacheEntries << std::endl;
            std::cout << "ClientActiveEntries      : " << response->ClientActiveEntries << std::endl;
            std::cout << "ServerActiveEntries      : " << response->ServerActiveEntries << std::endl;
            std::cout << "ClientHandshakesPerSecond: " << response->ClientHandshakesPerSecond << std::endl;
            std::cout << "ServerHandshakesPerSecond: " << response->ServerHandshakesPerSecond << std::endl;
            std::cout << "ClientReconnectsPerSecond: " << response->ClientReconnectsPerSecond << std::endl;
            std::cout << "ServerReconnectsPerSecond: " << response->ServerReconnectsPerSecond << std::endl;
        }
        return result;
    }

    bool PurgeCache(PLUID logonId, const std::wstring& serverName, ULONG flags) {
        PURGE_SESSION_CACHE_REQUEST request;
        request.LogonId.LowPart = logonId->LowPart;
        request.LogonId.HighPart = logonId->HighPart;
        UnicodeString serverNameGuard{ serverName };
        request.ServerName = serverNameGuard;
        request.Flags = flags;
        void* response;
        return CallPackage(request, &response);
    }

    bool StreamSizes() {
        STREAM_SIZES_REQUEST request;
        PSTREAM_SIZES_RESPONSE response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            std::cout << "unknown1: " << response->unknown[0] << std::endl;
            std::cout << "unknown2: " << response->unknown[1] << std::endl;
            std::cout << "unknown3: " << response->unknown[2] << std::endl;
        }
        return result;
    }
}