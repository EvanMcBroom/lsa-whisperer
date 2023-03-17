#define _NTDEF_ // Required to include both Ntsecapi and Winternl
#include <Winternl.h>
#include <codecvt>
#include <crypt.hpp>
#include <cxxopts.hpp>
#include <iostream>
#include <lsa.hpp>
#include <magic_enum.hpp>
#include <schannel.h>
#include <schannel.hpp>
#include <string>
#include <vector>

namespace Schannel {
    Proxy::Proxy(const std::shared_ptr<Lsa>& lsa)
        : lsa(lsa) {
    }

    bool Proxy::CacheInfo(PLUID logonId, const std::wstring& serverName, ULONG flags) const {
        SESSION_CACHE_INFO_REQUEST request;
        request.LogonId.LowPart = logonId->LowPart;
        request.LogonId.HighPart = logonId->HighPart;
        UnicodeString serverNameGuard{ serverName };
        request.ServerName = serverNameGuard;
        request.Flags = flags;
        void* response;
        return CallPackage(request, &response);
    }

    bool Proxy::LookupCert(const std::vector<byte>& certificate, ULONG flags, std::vector<std::vector<byte>> issuers) const {
        //CERT_LOGON_REQUEST request;
        //request.LogonInformation = logonInfo;
        //request.ValidationInformation = validationInfo;
        //request.SupplementalCacheData = const_cast<byte*>(supplementalCacheData.data());
        //request.SupplementalCacheDataLength = supplementalCacheData.size();
        //void* response;
        //return CallPackage(request, &response);
        return false;
    }

    bool Proxy::LookupExternalCert(ULONG type, const std::vector<byte>& credential, ULONG flags) const {
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

    bool Proxy::PerfmonInfo(ULONG flags) const {
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

    bool Proxy::PurgeCache(PLUID logonId, const std::wstring& serverName, ULONG flags) const {
        PURGE_SESSION_CACHE_REQUEST request;
        request.LogonId.LowPart = logonId->LowPart;
        request.LogonId.HighPart = logonId->HighPart;
        UnicodeString serverNameGuard{ serverName };
        request.ServerName = serverNameGuard;
        request.Flags = flags;
        void* response;
        return CallPackage(request, &response);
    }

    bool Proxy::StreamSizes() const {
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

    template<typename _Request, typename _Response>
    bool Proxy::CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const {
        if (lsa->Connected()) {
            std::string stringSubmitBuffer(reinterpret_cast<const char*>(&submitBuffer), sizeof(decltype(submitBuffer)));
            return lsa->CallPackage(UNISP_NAME_A, stringSubmitBuffer, reinterpret_cast<void**>(returnBuffer));
        }
        return false;
    }

    bool HandleFunction(std::ostream& out, const Proxy& proxy, const std::string& function, const cxxopts::ParseResult& options) {
        switch (magic_enum::enum_cast<PROTOCOL_MESSAGE_TYPE>(function).value()) {
        case PROTOCOL_MESSAGE_TYPE::CacheInfo: {
            return false; // CacheInfo();
        }
        case PROTOCOL_MESSAGE_TYPE::LookupCert:
            return false; // LookupCert();
        case PROTOCOL_MESSAGE_TYPE::LookupExternalCert: {
            return false; // return LookupExternalCert();
        }
        case PROTOCOL_MESSAGE_TYPE::PerfmonInfo: {
            DWORD flags{ 0 }; // The flags are ignored by the dispatch function
            return proxy.PerfmonInfo(flags);
        }
        case PROTOCOL_MESSAGE_TYPE::PurgeCache: {
            LUID luid;
            reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            auto server{ converter.from_bytes(options["server"].as<std::string>()) };
            DWORD flags{ 0 };
            flags |= (options.count("client-entry")) ? static_cast<ULONG>(Schannel::PurgeEntriesType::Client) : 0;
            flags |= (options.count("server-entry")) ? static_cast<ULONG>(Schannel::PurgeEntriesType::Server) : 0;
            flags |= (options.count("clients")) ? static_cast<ULONG>(Schannel::PurgeEntriesType::ClientAll) : 0;
            flags |= (options.count("servers")) ? static_cast<ULONG>(Schannel::PurgeEntriesType::ServerAll) : 0;
            flags |= (options.count("locators")) ? static_cast<ULONG>(Schannel::PurgeEntriesType::ServerEntriesDisardLocators) : 0;
            return proxy.PurgeCache(&luid, server, flags);
        }
        case PROTOCOL_MESSAGE_TYPE::StreamSizes:
            return proxy.StreamSizes();
        default:
            out << "Unsupported function" << std::endl;
            return false;
        }
    }

    void Parse(std::ostream& out, const std::vector<std::string>& args) {
        char* command{ "schannel" };
        cxxopts::Options options{ command };

        options.add_options("Schannel Function")("f,function", "Function name", cxxopts::value<std::string>());

        // Arguments for functions that require additional inputs
        options.add_options("Function arguments")("server", "Server name", cxxopts::value<std::string>())("luid", "Logon session", cxxopts::value<long long>())("clients", "All clients flag", cxxopts::value<bool>()->default_value("false"))("client-entry", "Client entry flag", cxxopts::value<bool>()->default_value("false"))("locators", "Purge locators flag", cxxopts::value<bool>()->default_value("false"))("servers", "All servers flag", cxxopts::value<bool>()->default_value("false"))("server-entry", "Server entry flag", cxxopts::value<bool>()->default_value("false"));

        try {
            std::vector<char*> argv;
            std::for_each(args.begin(), args.end(), [&argv](const std::string& arg) {
                argv.push_back(const_cast<char*>(arg.data()));
            });
            if (argv.size() > 1) {
                auto function{ argv[1] };
                auto result{ options.parse(argv.size(), argv.data()) };
                Proxy proxy{ std::make_shared<Lsa>(out) };
                HandleFunction(out, proxy, function, result);
            } else {
                out << options.help() << std::endl;
            }
        } catch (const std::exception& exception) {
            out << exception.what() << std::endl;
        }
    }
}