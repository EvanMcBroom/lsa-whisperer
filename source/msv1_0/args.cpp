#include <codecvt>
#include <crypt.hpp>
#include <magic_enum.hpp>
#include <msv1_0/args.hpp>
#include <msv1_0/cache.hpp>
#include <msv1_0/proxy.hpp>

namespace Msv1_0 {
    bool HandleFunction(std::ostream& out, const Proxy& proxy, const cxxopts::ParseResult& result) {
        switch (magic_enum::enum_cast<PROTOCOL_MESSAGE_TYPE>(result["function"].as<std::string>()).value()) {
        case PROTOCOL_MESSAGE_TYPE::CacheLogon: {
            // Populate the logon info
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            auto domain{ converter.from_bytes(result["domain"].as<std::string>()) };
            auto account{ converter.from_bytes(result["account"].as<std::string>()) };
            auto computer{ std::wstring((result.count("computer")) ? converter.from_bytes(result["computer"].as<std::string>()) : L"") };
            std::vector<byte> hash;
            if (result.count("hash")) {
                hash = HexDecode(out, converter.from_bytes(result["hash"].as<std::string>()));
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
                requestFlags |= static_cast<ULONG>(CacheLogonFlags::RequestMitLogon);
                auto upn{ converter.from_bytes(result["mitlogon"].as<std::string>()) };
                supplementalCreds = GetSupplementalMitCreds(domain, upn);
            }
            if (result.count("suppcreds")) {
                supplementalCreds = HexDecode(out, converter.from_bytes(result["suppcreds"].as<std::string>()));
            }
            // Set any additional flags that may have been specified
            requestFlags |= (result.count("delete")) ? static_cast<ULONG>(CacheLogonFlags::DeleteEntry) : 0;
            requestFlags |= (result.count("smartcard")) ? static_cast<ULONG>(CacheLogonFlags::RequestSmartcardOnly) : 0;
            void* response{ nullptr };
            return proxy.CacheLogon(logonInfo.get(), &validationInfo4, supplementalCreds, requestFlags);
        }
        case PROTOCOL_MESSAGE_TYPE::CacheLookupEx:
            break;
        case PROTOCOL_MESSAGE_TYPE::ChangeCachedPassword: {
            //auto domain{ result["domain"].as<std::string>() };
            //auto account{ result["account"].as<std::string>() };
            //auto oldpass{ result["oldpass"].as<std::string>() };
            //auto newpass{ result["newpass"].as<std::string>() };
            //return ChangeCachedPassword(domain, account, oldpass, newpass, result["imp"].as<bool>());
        }
        case PROTOCOL_MESSAGE_TYPE::ClearCachedCredentials:
            return proxy.ClearCachedCredentials();
        case PROTOCOL_MESSAGE_TYPE::DecryptDpapiMasterKey:
            return proxy.DecryptDpapiMasterKey();
        case PROTOCOL_MESSAGE_TYPE::DeleteTbalSecrets:
            return proxy.DeleteTbalSecrets();
        case PROTOCOL_MESSAGE_TYPE::DeriveCredential: {
            LUID luid;
            reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = result["luid"].as<long long>();
            auto credType{ (result.count("sha1v2")) ? DeriveCredType::Sha1V2 : DeriveCredType::Sha1 };
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            std::vector<byte> mixingBits;
            mixingBits = HexDecode(out, converter.from_bytes(result["mixingbits"].as<std::string>()));
            return proxy.DeriveCredential(&luid, credType, mixingBits);
        }
        case PROTOCOL_MESSAGE_TYPE::EnumerateUsers:
            return proxy.EnumerateUsers((result.count("dc")));
        case PROTOCOL_MESSAGE_TYPE::GetCredentialKey: {
            LUID luid;
            reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = result["luid"].as<long long>();
            return proxy.GetCredentialKey(&luid);
        }
        case PROTOCOL_MESSAGE_TYPE::GetStrongCredentialKey:
            return false;
        case PROTOCOL_MESSAGE_TYPE::GetUserInfo: {
            LUID luid;
            reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = result["luid"].as<long long>();
            return proxy.GetUserInfo(&luid);
        }
        case PROTOCOL_MESSAGE_TYPE::Lm20ChallengeRequest:
            return proxy.Lm20ChallengeRequest();
        case PROTOCOL_MESSAGE_TYPE::ProvisionTbal: {
            LUID luid;
            reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = result["luid"].as<long long>();
            return proxy.ProvisionTbal(&luid);
        }
        case PROTOCOL_MESSAGE_TYPE::SetProcessOption:
            return proxy.SetProcessOption(magic_enum::enum_cast<ProcessOption>(result["option"].as<std::string>()).value(), result["disable"].as<bool>());
        case PROTOCOL_MESSAGE_TYPE::TransferCred: {
            LUID sourceLuid, destinationLuid;
            reinterpret_cast<LARGE_INTEGER*>(&sourceLuid)->QuadPart = result["sluid"].as<long long>();
            reinterpret_cast<LARGE_INTEGER*>(&destinationLuid)->QuadPart = result["dluid"].as<long long>();
            return proxy.TransferCred(&sourceLuid, &destinationLuid);
        }
        default:
            out << "Unsupported function" << std::endl;
            return false;
        }
        return false;
    }

    void Parse(std::ostream& out, const std::vector<std::string>& args) {
        char* command{ "msv1_0" };
        cxxopts::Options options{ command };

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
            ("dluid", "Destination logon session", cxxopts::value<long long>())
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
            ("sluid", "Source logon session", cxxopts::value<long long>())
            ("smartcard", "Set smart card flag", cxxopts::value<bool>()->default_value("false"))
            ("suppcreds", "Asciihex supplemental creds", cxxopts::value<std::string>())
            ;

        try {
            std::vector<char*> argv{ command };
            std::for_each(args.begin(), args.end(), [&argv](const std::string& arg) {
                argv.push_back(const_cast<char*>(arg.data()));
            });
            auto result{ options.parse(argv.size(), argv.data()) };
            if (result.count("function")) {
                auto lsa{ std::make_shared<Lsa>(out) };
                Proxy proxy{ lsa };
                HandleFunction(out, proxy, result);
            }
            else {
                out << options.help() << std::endl;
            }
        }
        catch (const std::exception& exception) {
            out << exception.what() << std::endl;
        }
    }
}