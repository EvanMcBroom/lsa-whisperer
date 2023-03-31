#include <codecvt>
#include <commands.hpp>
#include <locale>
#include <magic_enum.hpp>
#include <string>

namespace Cloudap {
    bool HandleFunction(std::ostream& out, const Proxy& proxy, const std::string& function, const cxxopts::ParseResult& options) {
        switch (magic_enum::enum_cast<PROTOCOL_MESSAGE_TYPE>(function).value()) {
        case PROTOCOL_MESSAGE_TYPE::ReinitPlugin:
            return proxy.ReinitPlugin();
        case PROTOCOL_MESSAGE_TYPE::GetTokenBlob: {
            LUID luid;
            reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            return proxy.GetTokenBlob(&luid);
        }
        case PROTOCOL_MESSAGE_TYPE::CallPluginGeneric:
            return false;
        case PROTOCOL_MESSAGE_TYPE::ProfileDeleted:
            return proxy.ProfileDeleted();
        case PROTOCOL_MESSAGE_TYPE::GetAuthenticatingProvider: {
            LUID luid;
            reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            return proxy.GetAuthenticatingProvider(&luid);
        }
        case PROTOCOL_MESSAGE_TYPE::RenameAccount:
            return proxy.RenameAccount();
        case PROTOCOL_MESSAGE_TYPE::RefreshTokenBlob:
            return proxy.RefreshTokenBlob();
        case PROTOCOL_MESSAGE_TYPE::GenARSOPwd:
            return proxy.GenARSOPwd();
        case PROTOCOL_MESSAGE_TYPE::SetTestParas:
            return proxy.SetTestParas(0);
        case PROTOCOL_MESSAGE_TYPE::TransferCreds:
            if (options.count("sluid") && options.count("dluid")) {
                LUID source;
                source.LowPart = options["sluid"].as<DWORD>();
                LUID destination;
                destination.LowPart = options["dluid"].as<DWORD>();
                return proxy.TransferCreds(&source, &destination);
            } else {
                std::cout << "A source or destination LUID was not specified." << std::endl;
                return false;
            }
            break;
        case PROTOCOL_MESSAGE_TYPE::ProvisionNGCNode:
            return proxy.ProvisionNGCNode();
        case PROTOCOL_MESSAGE_TYPE::GetPwdExpiryInfo:
            return proxy.GetPwdExpiryInfo(nullptr, nullptr);
        case PROTOCOL_MESSAGE_TYPE::DisableOptimizedLogon:
            return proxy.DisableOptimizedLogon();
        case PROTOCOL_MESSAGE_TYPE::GetUnlockKeyType:
            return proxy.GetUnlockKeyType();
        case PROTOCOL_MESSAGE_TYPE::GetPublicCachedInfo:
            return proxy.GetPublicCachedInfo();
        case PROTOCOL_MESSAGE_TYPE::GetAccountInfo:
            return proxy.GetAccountInfo();
        case PROTOCOL_MESSAGE_TYPE::GetDpApiCredKeyDecryptStatus:
            return proxy.GetDpApiCredKeyDecryptStatus();
        case PROTOCOL_MESSAGE_TYPE::IsCloudToOnPremTgtPresentInCache:
            return proxy.IsCloudToOnPremTgtPresentInCache();
        default:
            break;
        }
        return false;
    }

    void Parse(std::ostream& out, const std::vector<std::string>& args) {
        char* command{ "cloudap" };
        cxxopts::Options options{ command };
        options.add_options("Command arguments")("luid", "Logon session", cxxopts::value<long long>());
        options.add_options("Function arguments")("aad", "Azure Active Directory", cxxopts::value<bool>()->default_value("false"))("dluid", "Destination logon session", cxxopts::value<unsigned int>())("disable", "Disable an option", cxxopts::value<std::string>())("enable", "Enable an option", cxxopts::value<std::string>())("msa", "Microsoft Account (e.g. Windows Live ID)", cxxopts::value<bool>()->default_value("false"))("sluid", "Source logon session", cxxopts::value<unsigned int>());
        ;

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

namespace Kerberos {
    bool HandleFunction(std::ostream& out, const Proxy& proxy, const std::string& function, const cxxopts::ParseResult& options) {
        switch (magic_enum::enum_cast<PROTOCOL_MESSAGE_TYPE>(function).value()) {
        case PROTOCOL_MESSAGE_TYPE::QueryTicketCache:
            LUID luid;
            reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            return proxy.QueryTicketCache(&luid);

        default:
            out << "Unsupported function" << std::endl;
            return false;
        }
    }

    void Parse(std::ostream& out, const std::vector<std::string>& args) {
        char* command{ "kerberos" };
        cxxopts::Options options{ command };
        options.allow_unrecognised_options();

        // Arguments for functions that require additional inputs
        options.add_options("Function arguments")("luid", "Logon session", cxxopts::value<long long>());

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

namespace Msv1_0 {
    bool HandleFunction(std::ostream& out, const Proxy& proxy, const std::string& function, const cxxopts::ParseResult& options) {
        switch (magic_enum::enum_cast<PROTOCOL_MESSAGE_TYPE>(function).value()) {
        case PROTOCOL_MESSAGE_TYPE::CacheLogon: {
            // Populate the logon info
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            auto domain{ converter.from_bytes(options["domain"].as<std::string>()) };
            auto account{ converter.from_bytes(options["account"].as<std::string>()) };
            auto computer{ std::wstring((options.count("computer")) ? converter.from_bytes(options["computer"].as<std::string>()) : L"") };
            std::vector<byte> hash;
            if (options.count("hash")) {
                hash = HexDecode(out, converter.from_bytes(options["hash"].as<std::string>()));
            } else {
                hash = CalculateNtOwfPassword(options["pass"].as<std::string>());
            }
            auto logonInfo{ Cache::GetLogonInfo(domain, account, computer, hash) };
            // Populate the validation info and supplemental creds
            ULONG requestFlags = static_cast<ULONG>(CacheLogonFlags::RequestInfo4);
            Netlogon::VALIDATION_SAM_INFO4 validationInfo4;
            std::memset(&validationInfo4, 0, sizeof(Netlogon::VALIDATION_SAM_INFO4));
            std::vector<byte> supplementalCreds;
            if (options.count("mitlogon")) {
                requestFlags |= static_cast<ULONG>(CacheLogonFlags::RequestMitLogon);
                auto upn{ converter.from_bytes(options["mitlogon"].as<std::string>()) };
                supplementalCreds = Cache::GetSupplementalMitCreds(domain, upn);
            }
            if (options.count("suppcreds")) {
                supplementalCreds = HexDecode(out, converter.from_bytes(options["suppcreds"].as<std::string>()));
            }
            // Set any additional flags that may have been specified
            requestFlags |= (options.count("delete")) ? static_cast<ULONG>(CacheLogonFlags::DeleteEntry) : 0;
            requestFlags |= (options.count("smartcard")) ? static_cast<ULONG>(CacheLogonFlags::RequestSmartcardOnly) : 0;
            void* response{ nullptr };
            return proxy.CacheLogon(logonInfo.get(), &validationInfo4, supplementalCreds, requestFlags);
        }
        case PROTOCOL_MESSAGE_TYPE::CacheLookupEx:
            break;
        case PROTOCOL_MESSAGE_TYPE::ChangeCachedPassword: {
            //auto domain{ options["domain"].as<std::string>() };
            //auto account{ options["account"].as<std::string>() };
            //auto oldpass{ options["oldpass"].as<std::string>() };
            //auto newpass{ options["newpass"].as<std::string>() };
            //return ChangeCachedPassword(domain, account, oldpass, newpass, options["imp"].as<bool>());
        }
        case PROTOCOL_MESSAGE_TYPE::ClearCachedCredentials:
            return proxy.ClearCachedCredentials();
        case PROTOCOL_MESSAGE_TYPE::DecryptDpapiMasterKey:
            return proxy.DecryptDpapiMasterKey();
        case PROTOCOL_MESSAGE_TYPE::DeleteTbalSecrets:
            return proxy.DeleteTbalSecrets();
        case PROTOCOL_MESSAGE_TYPE::DeriveCredential: {
            LUID luid;
            reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            auto credType{ (options.count("sha1v2")) ? DeriveCredType::Sha1V2 : DeriveCredType::Sha1 };
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            std::vector<byte> mixingBits;
            mixingBits = HexDecode(out, converter.from_bytes(options["mixingbits"].as<std::string>()));
            return proxy.DeriveCredential(&luid, credType, mixingBits);
        }
        case PROTOCOL_MESSAGE_TYPE::EnumerateUsers:
            return proxy.EnumerateUsers();
        case PROTOCOL_MESSAGE_TYPE::GetCredentialKey: {
            LUID luid;
            reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            return proxy.GetCredentialKey(&luid);
        }
        case PROTOCOL_MESSAGE_TYPE::GetStrongCredentialKey:
            return false;
        case PROTOCOL_MESSAGE_TYPE::GetUserInfo: {
            LUID luid;
            reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            return proxy.GetUserInfo(&luid);
        }
        case PROTOCOL_MESSAGE_TYPE::Lm20ChallengeRequest:
            return proxy.Lm20ChallengeRequest();
        case PROTOCOL_MESSAGE_TYPE::ProvisionTbal: {
            LUID luid;
            reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            return proxy.ProvisionTbal(&luid);
        }
        case PROTOCOL_MESSAGE_TYPE::SetProcessOption:
            return proxy.SetProcessOption(magic_enum::enum_cast<ProcessOption>(options["option"].as<std::string>()).value(), options["disable"].as<bool>());
        case PROTOCOL_MESSAGE_TYPE::TransferCred: {
            LUID sourceLuid, destinationLuid;
            reinterpret_cast<LARGE_INTEGER*>(&sourceLuid)->QuadPart = options["sluid"].as<long long>();
            reinterpret_cast<LARGE_INTEGER*>(&destinationLuid)->QuadPart = options["dluid"].as<long long>();
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
        options.allow_unrecognised_options();
        options.add_options()("d,dc", "Send request to domain controller", cxxopts::value<bool>()->default_value("false"));
        options.add_options("Function arguments")("account", "Account name", cxxopts::value<std::string>())("computer", "Computer name", cxxopts::value<std::string>())("delete", "Delete entry", cxxopts::value<bool>()->default_value("false"))("disable", "Disable an option", cxxopts::value<bool>()->default_value("false"))("dluid", "Destination logon session", cxxopts::value<long long>())("domain", "Domain name", cxxopts::value<std::string>())("hash", "Asciihex hash", cxxopts::value<std::string>())("imp", "Impersonating", cxxopts::value<bool>()->default_value("false"))("luid", "Logon session", cxxopts::value<long long>())("mitlogon", "Upn for Mit logon", cxxopts::value<std::string>())("mixingbits", "Asciihex mixing data", cxxopts::value<std::string>())("newpass", "New password", cxxopts::value<std::string>())("oldpass", "Old password", cxxopts::value<std::string>())("option", "Process option", cxxopts::value<std::string>())("pass", "Password", cxxopts::value<std::string>())("sha1v2", "Use SHA OWF instead of NT OWF", cxxopts::value<bool>()->default_value("false"))("sluid", "Source logon session", cxxopts::value<long long>())("smartcard", "Set smart card flag", cxxopts::value<bool>()->default_value("false"))("suppcreds", "Asciihex supplemental creds", cxxopts::value<std::string>());

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

namespace Negotiate {
    bool HandleFunction(std::ostream& out, const Proxy& proxy, const std::string& function, const cxxopts::ParseResult& options) {
        switch (magic_enum::enum_cast<PROTOCOL_MESSAGE_TYPE>(function).value()) {
        case PROTOCOL_MESSAGE_TYPE::EnumPackagePrefixes:
            return proxy.EnumPackagePrefixes();
        case PROTOCOL_MESSAGE_TYPE::GetCallerName: {
            LUID luid;
            reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            return proxy.GetCallerName(&luid);
        }
        default:
            out << "Unsupported function" << std::endl;
            return false;
        }
    }

    void Parse(std::ostream& out, const std::vector<std::string>& args) {
        char* command{ "negotiate" };
        cxxopts::Options options{ command };

        options.add_options("Command arguments")("luid", "Logon session", cxxopts::value<long long>());

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

namespace Pku2u {
    bool HandleFunction(std::ostream& out, const Proxy& proxy, const std::string& function, const cxxopts::ParseResult& options) {
        switch (magic_enum::enum_cast<PROTOCOL_MESSAGE_TYPE>(function).value()) {
        case PROTOCOL_MESSAGE_TYPE::PurgeTicketEx:
            return proxy.PurgeTicketEx();
        case PROTOCOL_MESSAGE_TYPE::QueryTicketCacheEx2: {
            LUID luid;
            reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            return proxy.QueryTicketCacheEx2(&luid);
        }
        default:
            out << "Unsupported function" << std::endl;
            return false;
        }
    }

    void Parse(std::ostream& out, const std::vector<std::string>& args) {
        char* command{ "pku2u" };
        cxxopts::Options options{ command };

        options.add_options("Command arguments")("luid", "Logon session", cxxopts::value<long long>());

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

namespace Schannel {
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

namespace Wdigest {
    bool HandleFunction(std::ostream& out, const Proxy& proxy, const cxxopts::ParseResult& options) {
        switch (magic_enum::enum_cast<PROTOCOL_MESSAGE_TYPE>(options["function"].as<std::string>()).value()) {
        case PROTOCOL_MESSAGE_TYPE::VerifyDigest:
            return false;
        default:
            break;
        }
        return false;
    }

    void Parse(std::ostream& out, const std::vector<std::string>& args) {
        char* command{ "wdigest" };
        cxxopts::Options options{ command };

        options.add_options("Wdigest Function")("f,function", "Function name", cxxopts::value<std::string>());
    }
}