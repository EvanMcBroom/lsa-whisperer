#include <Windows.h>
#include <args.hpp>
#include <cache.hpp>
#include <codecvt>
#include <crypt.hpp>
#include <magic_enum.hpp>
#include <msv1_0.hpp>

using namespace MSV1_0;

bool HandleFunction(const cxxopts::ParseResult& result) {
    switch (magic_enum::enum_cast<PROTOCOL_MESSAGE_TYPE>(result["function"].as<std::string>()).value()) {
    case PROTOCOL_MESSAGE_TYPE::CacheLogon: {
        // Populate the logon info
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        auto domain{ converter.from_bytes(result["domain"].as<std::string>()) };
        auto account{ converter.from_bytes(result["account"].as<std::string>()) };
        auto computer{ std::wstring((result.count("computer")) ? converter.from_bytes(result["computer"].as<std::string>()) : L"") };
        std::vector<byte> hash;
        if (result.count("hash")) {
            hash = HexDecode(converter.from_bytes(result["hash"].as<std::string>()));
        }
        else {
            hash = CalculateNtOwfPassword(result["pass"].as<std::string>());
        }
        auto logonInfo{ GetLogonInfo(domain, account, computer, hash) };
        // Populate the validation info and supplemental creds
        ULONG requestFlags = static_cast<ULONG>(CacheLogonFlags::RequestInfo4);
        Netlogon::VALIDATION_SAM_INFO4 validationInfo4;
        std::memset(&validationInfo4, 0, sizeof(Netlogon::VALIDATION_SAM_INFO4));
        std::vector<byte> supplementalCreds;
        if (result.count("mitlogon")) {
            requestFlags |= static_cast<ULONG>(MSV1_0::CacheLogonFlags::RequestMitLogon);
            auto upn{ converter.from_bytes(result["mitlogon"].as<std::string>()) };
            supplementalCreds = GetSupplementalMitCreds(domain, upn);
        }
        if (result.count("suppcreds")) {
            supplementalCreds = HexDecode(converter.from_bytes(result["suppcreds"].as<std::string>()));
        }
        // Set any additional flags that may have been specified
        requestFlags |= (result.count("delete")) ? static_cast<ULONG>(MSV1_0::CacheLogonFlags::DeleteEntry) : 0;
        requestFlags |= (result.count("smartcard")) ? static_cast<ULONG>(MSV1_0::CacheLogonFlags::RequestSmartcardOnly) : 0;
        void* response{ nullptr };
        return CacheLogon(logonInfo.get(), &validationInfo4, supplementalCreds, requestFlags);
    }
    case PROTOCOL_MESSAGE_TYPE::CacheLookupEx:
        break;
    case PROTOCOL_MESSAGE_TYPE::Lm20ChallengeRequest:
        return Lm20ChallengeRequest();
    case PROTOCOL_MESSAGE_TYPE::ChangeCachedPassword: {
        //auto domain{ result["domain"].as<std::string>() };
        //auto account{ result["account"].as<std::string>() };
        //auto oldpass{ result["oldpass"].as<std::string>() };
        //auto newpass{ result["newpass"].as<std::string>() };
        //return ChangeCachedPassword(domain, account, oldpass, newpass, result["imp"].as<bool>());
    }
    case PROTOCOL_MESSAGE_TYPE::ClearCachedCredentials:
        return ClearCachedCredentials();
    case PROTOCOL_MESSAGE_TYPE::DecryptDpapiMasterKey:
        break;
    case PROTOCOL_MESSAGE_TYPE::DeleteTbalSecrets:
        return DeleteTbalSecrets();
    case PROTOCOL_MESSAGE_TYPE::DeriveCredential: {
        LUID luid;
        reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = result["luid"].as<long long>();
        auto credType{ (result.count("sha1v2")) ? DeriveCredType::Sha1V2 : DeriveCredType::Sha1 };
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        std::vector<byte> mixingBits;
        mixingBits = HexDecode(converter.from_bytes(result["mixingbits"].as<std::string>()));
        return DeriveCredential(&luid, credType, mixingBits);
    }
    case PROTOCOL_MESSAGE_TYPE::EnumerateUsers:
        return EnumerateUsers((result.count("dc")));
    case PROTOCOL_MESSAGE_TYPE::GetCredentialKey: {
        LUID luid;
        reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = result["luid"].as<long long>();
        return GetCredentialKey(&luid);
    }
    case PROTOCOL_MESSAGE_TYPE::GetStrongCredentialKey:
        return false;
    case PROTOCOL_MESSAGE_TYPE::GetUserInfo: {
        LUID luid;
        reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = result["luid"].as<long long>();
        return GetUserInfo(&luid);
    }
    case PROTOCOL_MESSAGE_TYPE::ProvisionTbal: {
        LUID luid;
        reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = result["luid"].as<long long>();
        return ProvisionTbal(&luid);
    }
    case PROTOCOL_MESSAGE_TYPE::SetProcessOption:
        return SetProcessOption(magic_enum::enum_cast<ProcessOption>(result["option"].as<std::string>()).value(), result["disable"].as<bool>());
    case PROTOCOL_MESSAGE_TYPE::TransferCred:
        //if (result.count("sluid") && result.count("dluid")) {
        //    LUID source;
        //    source.LowPart = result["sluid"].as<DWORD>();
        //    LUID destination;
        //    destination.LowPart = result["sluid"].as<DWORD>();
        //    return TransferCreds(source, destination);
        //}
        //else {
        //    std::cout << "A source or destination LUID was not specified." << std::endl;
        //    return -1;
        //}
        break;
    default:
        std::cout << "Unsupported function" << std::endl;
        break;
    }
}

int Parse(int argc, char** argv) {
    cxxopts::Options options{ "msv-cli", "A CLI for the MSV1_0 authentication package" };

    options.add_options("MSV1_0 Function")
        ("d,dc", "Send request to domain controller", cxxopts::value<bool>()->default_value("false"))
        ("f,function", "Function name", cxxopts::value<std::string>())
        ;

    // Arguments for functions that require additional inputs
    options.add_options("Function arguments")
        ("account", "Account name", cxxopts::value<std::string>())
        ("computer", "Computer name", cxxopts::value<std::string>())
        ("delete", "Delete entry", cxxopts::value<bool>()->default_value("false"))
        ("disable", "Disable an option", cxxopts::value<bool>()->default_value("false"))
        ("domain", "Domain name", cxxopts::value<std::string>())
        ("hash", "Asciihex hash", cxxopts::value<std::string>())
        ("imp", "Impersonating", cxxopts::value<bool>()->default_value("false"))
        ("luid", "Logon session", cxxopts::value<long long>())
        ("mitlogon", "Upn for Mit logon", cxxopts::value<std::string>())
        ("mixingbits", "Asciihex mixing data", cxxopts::value<std::string>())
        ("newpass", "New password", cxxopts::value<std::string>())
        ("oldpass", "Old password", cxxopts::value<std::string>())
        ("option", "Process option", cxxopts::value<std::string>())
        ("pass", "Password", cxxopts::value<std::string>())
        ("sha1v2", "Use SHA OWF instead of NT OWF", cxxopts::value<bool>()->default_value("false"))
        ("smartcard", "Set smart card flag", cxxopts::value<bool>()->default_value("false"))
        ("suppcreds", "Asciihex supplemental creds", cxxopts::value<std::string>())
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