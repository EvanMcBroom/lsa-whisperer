#include <cxxopts.hpp>
#include <codecvt>
#include <crypt.hpp>
#include <magic_enum.hpp>
#include <schannel/args.hpp>
#include <schannel/messages.hpp>
#include <schannel/stubs.hpp>

using namespace Schannel;

bool HandleFunction(const cxxopts::ParseResult& result) {
    switch (magic_enum::enum_cast<PROTOCOL_MESSAGE_TYPE>(result["function"].as<std::string>()).value()) {
    case PROTOCOL_MESSAGE_TYPE::CacheInfo: {
        // Populate the logon info
        //std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        //auto domain{ converter.from_bytes(result["domain"].as<std::string>()) };
        //auto account{ converter.from_bytes(result["account"].as<std::string>()) };
        //auto computer{ std::wstring((result.count("computer")) ? converter.from_bytes(result["computer"].as<std::string>()) : L"") };
        //std::vector<byte> hash;
        //if (result.count("hash")) {
        //    hash = HexDecode(converter.from_bytes(result["hash"].as<std::string>()));
        //}
        //else {
        //    hash = CalculateNtOwfPassword(result["pass"].as<std::string>());
        //}
        //auto logonInfo{ GetLogonInfo(domain, account, computer, hash) };
        //// Populate the validation info and supplemental creds
        //ULONG requestFlags = static_cast<ULONG>(CacheLogonFlags::RequestInfo4);
        //Netlogon::VALIDATION_SAM_INFO4 validationInfo4;
        //std::memset(&validationInfo4, 0, sizeof(Netlogon::VALIDATION_SAM_INFO4));
        //std::vector<byte> supplementalCreds;
        //if (result.count("mitlogon")) {
        //    requestFlags |= static_cast<ULONG>(MSV1_0::CacheLogonFlags::RequestMitLogon);
        //    auto upn{ converter.from_bytes(result["mitlogon"].as<std::string>()) };
        //    supplementalCreds = GetSupplementalMitCreds(domain, upn);
        //}
        //if (result.count("suppcreds")) {
        //    supplementalCreds = HexDecode(converter.from_bytes(result["suppcreds"].as<std::string>()));
        //}
        //// Set any additional flags that may have been specified
        //requestFlags |= (result.count("delete")) ? static_cast<ULONG>(MSV1_0::CacheLogonFlags::DeleteEntry) : 0;
        //requestFlags |= (result.count("smartcard")) ? static_cast<ULONG>(MSV1_0::CacheLogonFlags::RequestSmartcardOnly) : 0;
        //void* response{ nullptr };
        //return CacheLogon(logonInfo.get(), &validationInfo4, supplementalCreds, requestFlags);
        return false;
    }
    case PROTOCOL_MESSAGE_TYPE::LookupCert:
        return false;// LookupCert();
    case PROTOCOL_MESSAGE_TYPE::LookupExternalCert: {
        //auto domain{ result["domain"].as<std::string>() };
        //auto account{ result["account"].as<std::string>() };
        //auto newpass{ result["newpass"].as<std::string>() };
        return false;// return LookupExternalCert(domain, account, oldpass, newpass, result["imp"].as<bool>());
    }
    case PROTOCOL_MESSAGE_TYPE::PerfmonInfo: {
        DWORD flags{ 0 }; // The flags are ignored by the dispatch function
        return PerfmonInfo(flags);
    }
    case PROTOCOL_MESSAGE_TYPE::PurgeCache: {
        LUID luid;
        reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = result["luid"].as<long long>();
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        auto server{ converter.from_bytes(result["server"].as<std::string>()) };
        DWORD flags{ 0 };
        flags |= (result.count("client-entry")) ? static_cast<ULONG>(Schannel::PurgeEntriesType::Client) : 0;
        flags |= (result.count("server-entry")) ? static_cast<ULONG>(Schannel::PurgeEntriesType::Server) : 0;
        flags |= (result.count("clients")) ? static_cast<ULONG>(Schannel::PurgeEntriesType::ClientAll) : 0;
        flags |= (result.count("servers")) ? static_cast<ULONG>(Schannel::PurgeEntriesType::ServerAll) : 0;
        flags |= (result.count("locators")) ? static_cast<ULONG>(Schannel::PurgeEntriesType::ServerEntriesDisardLocators) : 0;
        return PurgeCache(&luid, server, flags);
    }
    case PROTOCOL_MESSAGE_TYPE::StreamSizes:
        return StreamSizes();
    default:
        std::cout << "Unsupported function" << std::endl;
        break;
    }
}

int Parse(int argc, char** argv) {
    cxxopts::Options options{ "schannel-cli", "A CLI for the schannel authentication package" };

    options.add_options("Schannel Function")
        ("f,function", "Function name", cxxopts::value<std::string>())
        ;

    // Arguments for functions that require additional inputs
    options.add_options("Function arguments")
        //("account", "Account name", cxxopts::value<std::string>())
        //("computer", "Computer name", cxxopts::value<std::string>())
        //("delete", "Delete entry", cxxopts::value<bool>()->default_value("false"))
        //("disable", "Disable an option", cxxopts::value<bool>()->default_value("false"))
        //("dluid", "Destination logon session", cxxopts::value<long long>())
        ("server", "Server name", cxxopts::value<std::string>())
        //("hash", "Asciihex hash", cxxopts::value<std::string>())
        //("imp", "Impersonating", cxxopts::value<bool>()->default_value("false"))
        ("luid", "Logon session", cxxopts::value<long long>())
        //("mitlogon", "Upn for Mit logon", cxxopts::value<std::string>())
        //("mixingbits", "Asciihex mixing data", cxxopts::value<std::string>())
        //("newpass", "New password", cxxopts::value<std::string>())
        //("oldpass", "Old password", cxxopts::value<std::string>())
        //("option", "Process option", cxxopts::value<std::string>())
        //("pass", "Password", cxxopts::value<std::string>())
        //("sha1v2", "Use SHA OWF instead of NT OWF", cxxopts::value<bool>()->default_value("false"))
        //("sluid", "Source logon session", cxxopts::value<long long>())
        ("clients", "All clients flag", cxxopts::value<bool>()->default_value("false"))
        ("client-entry", "Client entry flag", cxxopts::value<bool>()->default_value("false"))
        ("locators", "Purge locators flag", cxxopts::value<bool>()->default_value("false"))
        ("servers", "All servers flag", cxxopts::value<bool>()->default_value("false"))
        ("server-entry", "Server entry flag", cxxopts::value<bool>()->default_value("false"))
        ;

    try {
        auto result{ options.parse(argc, argv) };
        if (result.count("function")) {
            return HandleFunction(result);
        }
        else {
            std::cout << options.help() << std::endl;
            return -1;
        }
    }
    catch (const std::exception& exception) {
        std::cout << exception.what() << std::endl;
    }
}