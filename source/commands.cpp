#include <codecvt>
#include <commands.hpp>
#include <locale>
#include <magic_enum.hpp>
#include <string>

namespace Cloudap {
    bool Call(const std::shared_ptr<Lsa>& lsa, const std::vector<char*>& args) {
        char* command{ "cloudap" };
        cxxopts::Options unparsedOptions{ command };
        // clang-format off
        unparsedOptions.add_options("Command arguments")
            ("luid", "Logon session", cxxopts::value<long long>());
        unparsedOptions.add_options("Function arguments")
            ("aad", "Azure Active Directory", cxxopts::value<bool>()->default_value("false"))
            ("authority", "Authority type (1 or 2)", cxxopts::value<unsigned int>())
            ("dluid", "Destination logon session", cxxopts::value<unsigned int>())
            ("disable", "Disable an option", cxxopts::value<std::string>())
            ("enable", "Enable an option", cxxopts::value<std::string>())
            ("msa", "Microsoft Account (e.g. Windows Live ID)", cxxopts::value<bool>()->default_value("false"))
            ("sluid", "Source logon session", cxxopts::value<unsigned int>());
        // clang-format on
        auto options{ unparsedOptions.parse(args.size(), args.data()) };
        if (!args.size()) {
            std::cout << unparsedOptions.help() << std::endl;
            return false;
        }
        if (options["aad"].count() && options["msa"].count()) {
            std::cout << "You may only specify one cloudap plugin." << std::endl;
            return false;
        } else if (options["aad"].count()) {
            auto proxy{ Aad::Proxy(lsa) };
            switch (magic_enum::enum_cast<PLUGIN_FUNCTION>(args[1]).value()) {
            case PLUGIN_FUNCTION::AcceptPeerCertificate:
                break;
            case PLUGIN_FUNCTION::AssembleOpaqueData:
                break;
            case PLUGIN_FUNCTION::DisassembleOpaqueData:
                break;
            case PLUGIN_FUNCTION::GenericCallPkg:
                break;
            case PLUGIN_FUNCTION::GetCertificateFromCred:
                break;
            case PLUGIN_FUNCTION::GetKeys:
                break;
            case PLUGIN_FUNCTION::GetToken:
                break;
            case PLUGIN_FUNCTION::GetUnlockKey:
                return proxy.GetUnlockKey(static_cast<AUTHORITY_TYPE>(options["authority"].as<unsigned int>()));
            case PLUGIN_FUNCTION::LookupIdentityFromSIDName:
                break;
            case PLUGIN_FUNCTION::LookupSIDFromIdentityName:
                break;
            case PLUGIN_FUNCTION::PluginUninitialize:
                break;
            case PLUGIN_FUNCTION::PostLogonProcessing:
                break;
            case PLUGIN_FUNCTION::RefreshToken:
                return proxy.RefreshToken();
            case PLUGIN_FUNCTION::ValidateUserInfo:
                break;
            default:
                break;
            }
            return false;
        } else if (options["msa"].count()) {
        } else {
            auto proxy{ Proxy(lsa) };
            switch (magic_enum::enum_cast<PROTOCOL_MESSAGE_TYPE>(args[1]).value()) {
            case PROTOCOL_MESSAGE_TYPE::CallPluginGeneric:
                return false;
            case PROTOCOL_MESSAGE_TYPE::DisableOptimizedLogon: {
                LUID luid;
                reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
                return proxy.DisableOptimizedLogon(&luid);
            }
            case PROTOCOL_MESSAGE_TYPE::GenARSOPwd:
                return proxy.GenARSOPwd();
            case PROTOCOL_MESSAGE_TYPE::GetAccountInfo:
                return proxy.GetAccountInfo();
            case PROTOCOL_MESSAGE_TYPE::GetAuthenticatingProvider: {
                LUID luid;
                reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
                return proxy.GetAuthenticatingProvider(&luid);
            }
            case PROTOCOL_MESSAGE_TYPE::GetDpApiCredKeyDecryptStatus: {
                LUID luid;
                reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
                return proxy.GetDpApiCredKeyDecryptStatus(&luid);
            }
            case PROTOCOL_MESSAGE_TYPE::GetPublicCachedInfo:
                return proxy.GetPublicCachedInfo();
            case PROTOCOL_MESSAGE_TYPE::GetPwdExpiryInfo: {
                LUID luid;
                reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
                return proxy.GetPwdExpiryInfo(&luid);
            }
            case PROTOCOL_MESSAGE_TYPE::GetTokenBlob: {
                LUID luid;
                reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
                return proxy.GetTokenBlob(&luid);
            }
            case PROTOCOL_MESSAGE_TYPE::GetUnlockKeyType: {
                LUID luid;
                reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
                return proxy.GetUnlockKeyType(&luid);
            }
            case PROTOCOL_MESSAGE_TYPE::IsCloudToOnPremTgtPresentInCache: {
                LUID luid;
                reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
                return proxy.IsCloudToOnPremTgtPresentInCache(&luid);
            }
            case PROTOCOL_MESSAGE_TYPE::ProfileDeleted:
                return proxy.ProfileDeleted();
            case PROTOCOL_MESSAGE_TYPE::ProvisionNGCNode:
                return proxy.ProvisionNGCNode();
            case PROTOCOL_MESSAGE_TYPE::RefreshTokenBlob:
                return proxy.RefreshTokenBlob();
            case PROTOCOL_MESSAGE_TYPE::ReinitPlugin:
                return proxy.ReinitPlugin();
            case PROTOCOL_MESSAGE_TYPE::RenameAccount:
                return proxy.RenameAccount();
            case PROTOCOL_MESSAGE_TYPE::SetTestParas:
                return proxy.SetTestParas(0);
            case PROTOCOL_MESSAGE_TYPE::TransferCreds: {
                LUID sourceLuid, destinationLuid;
                reinterpret_cast<LARGE_INTEGER*>(&sourceLuid)->QuadPart = options["sluid"].as<long long>();
                reinterpret_cast<LARGE_INTEGER*>(&destinationLuid)->QuadPart = options["dluid"].as<long long>();
                return proxy.TransferCreds(&sourceLuid, &destinationLuid);
            }
            default:
                break;
            }
            return false;
        }
    }
}

namespace Kerberos {
    bool Call(const std::shared_ptr<Lsa>& lsa, const std::vector<char*>& args) {
        char* command{ "kerberos" };
        cxxopts::Options unparsedOptions{ command };
        unparsedOptions.allow_unrecognised_options();
        // clang-format off
        unparsedOptions.add_options("Function arguments")
            ("cleanup-credentials", "Cleanup credentials flag", cxxopts::value<bool>()->default_value("false"))
            ("dluid", "Destination logon session", cxxopts::value<long long>())
            ("luid", "Logon session", cxxopts::value<long long>())
            ("optimistic-logon", "Optimistic logon flag", cxxopts::value<bool>()->default_value("false"))
            ("sluid", "Source logon session", cxxopts::value<long long>());
        // clang-format on
        if (!args.size()) {
            std::cout << unparsedOptions.help() << std::endl;
            return false;
        }
        auto options{ unparsedOptions.parse(args.size(), args.data()) };
        auto proxy{ Proxy(lsa) };

        switch (magic_enum::enum_cast<PROTOCOL_MESSAGE_TYPE>(args[1]).value()) {
        case PROTOCOL_MESSAGE_TYPE::QueryTicketCache:
            LUID luid;
            reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            return proxy.QueryTicketCache(&luid);
        case PROTOCOL_MESSAGE_TYPE::TransferCredentials: {
            LUID sourceLuid, destinationLuid;
            reinterpret_cast<LARGE_INTEGER*>(&sourceLuid)->QuadPart = options["sluid"].as<long long>();
            reinterpret_cast<LARGE_INTEGER*>(&destinationLuid)->QuadPart = options["dluid"].as<long long>();
            ULONG flags{ 0 };
            flags += (options.count("cleanup-credentials")) ? static_cast<ULONG>(TransferCredFlag::CleanupCredentials) : 0;
            flags += (options.count("optimistic-logon")) ? static_cast<ULONG>(TransferCredFlag::OptimisticLogon) : 0;
            return proxy.TransferCreds(&sourceLuid, &destinationLuid, flags);
        }
        default:
            std::cout << "Unsupported function" << std::endl;
            return false;
        }
    }
}

namespace Msv1_0 {
    bool Call(const std::shared_ptr<Lsa>& lsa, const std::vector<char*>& args) {
        char* command{ "msv1_0" };
        cxxopts::Options unparsedOptions{ command };
        unparsedOptions.allow_unrecognised_options();
        // clang-format off
        unparsedOptions.add_options()
            ("d,dc", "Send request to domain controller", cxxopts::value<bool>()->default_value("false"));
        unparsedOptions.add_options("Function arguments")
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
            ("suppcreds", "Asciihex supplemental creds", cxxopts::value<std::string>());
        // clang-format on
        if (!args.size()) {
            std::cout << unparsedOptions.help() << std::endl;
            return false;
        }
        auto options{ unparsedOptions.parse(args.size(), args.data()) };
        auto proxy{ Proxy(lsa) };

        switch (magic_enum::enum_cast<PROTOCOL_MESSAGE_TYPE>(args[1]).value()) {
        case PROTOCOL_MESSAGE_TYPE::CacheLogon: {
            // Populate the logon info
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            auto domain{ converter.from_bytes(options["domain"].as<std::string>()) };
            auto account{ converter.from_bytes(options["account"].as<std::string>()) };
            auto computer{ std::wstring((options.count("computer")) ? converter.from_bytes(options["computer"].as<std::string>()) : L"") };
            std::vector<byte> hash;
            if (options.count("hash")) {
                hash = HexDecode(std::cout, converter.from_bytes(options["hash"].as<std::string>()));
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
                supplementalCreds = HexDecode(std::cout, converter.from_bytes(options["suppcreds"].as<std::string>()));
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
            mixingBits = HexDecode(std::cout, converter.from_bytes(options["mixingbits"].as<std::string>()));
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
            std::cout << "Unsupported function" << std::endl;
            return false;
        }
        return false;
    }
}

namespace Negotiate {
    bool Call(const std::shared_ptr<Lsa>& lsa, const std::vector<char*>& args) {
        char* command{ "negotiate" };
        cxxopts::Options unparsedOptions{ command };
        // clang-format off
        unparsedOptions.add_options("Command arguments")
            ("cleanup-credentials", "Cleanup credentials flag", cxxopts::value<bool>()->default_value("false"))
            ("luid", "Logon session", cxxopts::value<long long>())
            ("optimistic-logon", "Optimistic logon flag", cxxopts::value<bool>()->default_value("false"))
            ("to-sso-session", "To SSO session flag", cxxopts::value<bool>()->default_value("false"));
        // clang-format on
        if (!args.size()) {
            std::cout << unparsedOptions.help() << std::endl;
            return false;
        }
        auto options{ unparsedOptions.parse(args.size(), args.data()) };
        auto proxy{ Proxy(lsa) };

        switch (magic_enum::enum_cast<PROTOCOL_MESSAGE_TYPE>(args[1]).value()) {
        case PROTOCOL_MESSAGE_TYPE::EnumPackagePrefixes:
            return proxy.EnumPackagePrefixes();
        case PROTOCOL_MESSAGE_TYPE::GetCallerName: {
            LUID luid;
            reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            return proxy.GetCallerName(&luid);
        }
        case PROTOCOL_MESSAGE_TYPE::TransferCred: {
            LUID sourceLuid, destinationLuid;
            reinterpret_cast<LARGE_INTEGER*>(&sourceLuid)->QuadPart = options["sluid"].as<long long>();
            reinterpret_cast<LARGE_INTEGER*>(&destinationLuid)->QuadPart = options["dluid"].as<long long>();
            ULONG flags{ 0 };
            flags += (options.count("cleanup-credentials")) ? static_cast<ULONG>(TransferCredFlag::CleanupCredentials) : 0;
            flags += (options.count("optimistic-logon")) ? static_cast<ULONG>(TransferCredFlag::OptimisticLogon) : 0;
            flags += (options.count("to-sso-session")) ? static_cast<ULONG>(TransferCredFlag::ToSsoSession) : 0;
            return proxy.TransferCreds(&sourceLuid, &destinationLuid, flags);
        }
        default:
            std::cout << "Unsupported function" << std::endl;
            return false;
        }
    }
}

namespace Pku2u {
    bool Call(const std::shared_ptr<Lsa>& lsa, const std::vector<char*>& args) {
        char* command{ "pku2u" };
        cxxopts::Options unparsedOptions{ command };
        // clang-format off
        unparsedOptions.add_options("Command arguments")
            ("all", "Purge all tickets flag", cxxopts::value<bool>()->default_value("false"))
            ("luid", "Logon session", cxxopts::value<long long>());
        // clang-format on
        if (!args.size()) {
            std::cout << unparsedOptions.help() << std::endl;
            return false;
        }
        auto options{ unparsedOptions.parse(args.size(), args.data()) };
        auto proxy{ Proxy(lsa) };

        switch (magic_enum::enum_cast<PROTOCOL_MESSAGE_TYPE>(args[1]).value()) {
        case PROTOCOL_MESSAGE_TYPE::PurgeTicketEx: {
            LUID luid;
            reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            auto flags{ (options.count("all")) ? KERB_PURGE_ALL_TICKETS : 0 };
            return proxy.PurgeTicketEx(&luid, flags);
        }
        case PROTOCOL_MESSAGE_TYPE::QueryTicketCacheEx2: {
            LUID luid;
            reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            return proxy.QueryTicketCacheEx2(&luid);
        }
        default:
            std::cout << "Unsupported function" << std::endl;
            return false;
        }
    }
}

namespace Schannel {
    bool Call(const std::shared_ptr<Lsa>& lsa, const std::vector<char*>& args) {
        char* command{ "schannel" };
        cxxopts::Options unparsedOptions{ command };
        unparsedOptions.add_options("Schannel Function")("f,function", "Function name", cxxopts::value<std::string>());
        // Arguments for functions that require additional inputs
        unparsedOptions.add_options("Function arguments")("server", "Server name", cxxopts::value<std::string>())("luid", "Logon session", cxxopts::value<long long>())("clients", "All clients flag", cxxopts::value<bool>()->default_value("false"))("client-entry", "Client entry flag", cxxopts::value<bool>()->default_value("false"))("locators", "Purge locators flag", cxxopts::value<bool>()->default_value("false"))("servers", "All servers flag", cxxopts::value<bool>()->default_value("false"))("server-entry", "Server entry flag", cxxopts::value<bool>()->default_value("false"));
        if (!args.size()) {
            std::cout << unparsedOptions.help() << std::endl;
            return false;
        }
        auto options{ unparsedOptions.parse(args.size(), args.data()) };
        auto proxy{ Proxy(lsa) };

        switch (magic_enum::enum_cast<PROTOCOL_MESSAGE_TYPE>(args[1]).value()) {
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
            std::cout << "Unsupported function" << std::endl;
            return false;
        }
    }
}

namespace Spm {
    bool Call(const std::shared_ptr<Lsa>& lsa, const std::vector<char*>& args) {
        char* command{ "spm" };
        cxxopts::Options unparsedOptions{ command };
        // clang-format off
        unparsedOptions.add_options("Spm Function")
            ("f,function", "Function name", cxxopts::value<std::string>());
        // clang-format on
        if (!args.size()) {
            std::cout << unparsedOptions.help() << std::endl;
            return false;
        }
        auto options{ unparsedOptions.parse(args.size(), args.data()) };

        switch (magic_enum::enum_cast<SpmApi::NUMBER>(args[1]).value()) {
        case SpmApi::NUMBER::EnumLogonSessions:
            return lsa->EnumLogonSessions();
        case SpmApi::NUMBER::EnumPackages:
            return lsa->EnumPackages();
        default:
            break;
        }
        return false;
    }
}

namespace Wdigest {
    bool Call(const std::shared_ptr<Lsa>& lsa, const std::vector<char*>& args) {
        char* command{ "wdigest" };
        cxxopts::Options unparsedOptions{ command };
        // clang-format off
        unparsedOptions.add_options("Wdigest Function")
            ("f,function", "Function name", cxxopts::value<std::string>());
        // clang-format on
        if (!args.size()) {
            std::cout << unparsedOptions.help() << std::endl;
            return false;
        }
        auto options{ unparsedOptions.parse(args.size(), args.data()) };
        auto proxy{ Proxy(lsa) };

        switch (magic_enum::enum_cast<PROTOCOL_MESSAGE_TYPE>(options["function"].as<std::string>()).value()) {
        case PROTOCOL_MESSAGE_TYPE::VerifyDigest:
            return false;
        default:
            break;
        }
        return false;
    }
}