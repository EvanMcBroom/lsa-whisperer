#include <Windows.h>
#include <cloudap.hpp>
#include <cxxopts.hpp>
#include <iostream>
#include <lsa.hpp>
#include <magic_enum.hpp>

namespace Cloudap {
    Proxy::Proxy(const std::shared_ptr<Lsa>& lsa)
        : lsa(lsa) {
    }

    bool Proxy::CallPluginGeneric(GUID* plugin, const std::string& json, void** returnBuffer) const {
        return false;
    }

    bool Proxy::DisableOptimizedLogon() const {
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::DisableOptimizedLogon);
    }

    bool Proxy::GenARSOPwd() const {
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::GenARSOPwd);
    }

    bool Proxy::GetAccountInfo() const { //xxx
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::GetAccountInfo);
    }

    bool Proxy::GetAuthenticatingProvider(GUID* authenticationProvider) const {
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::GetAuthenticatingProvider);
    }

    bool Proxy::GetDpApiCredKeyDecryptStatus() const {
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::GetDpApiCredKeyDecryptStatus);
    }

    bool Proxy::GetPublicCachedInfo() const {
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::GetPublicCachedInfo);
    }

    bool Proxy::GetPwdExpiryInfo(PFILETIME expiryTime, std::string* expiryTimeString) const {
        auto request{ PROTOCOL_MESSAGE_TYPE::GetPwdExpiryInfo };
        void* response{ nullptr };
        auto status{ CallPackage(request, &response) };
        return status;
    }

    bool Proxy::GetTokenBlob(void** tokenBlob) const {
        auto request{ PROTOCOL_MESSAGE_TYPE::GetTokenBlob };
        void* response;
        auto status{ CallPackage(request, &response) };
        return status;
    }

    bool Proxy::GetUnlockKeyType() const {
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::GetUnlockKeyType);
    }

    bool Proxy::IsCloudToOnPremTgtPresentInCache() const {
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::IsCloudToOnPremTgtPresentInCache);
    }

    bool Proxy::ProfileDeleted() const {
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::ProfileDeleted);
    }

    bool Proxy::ProvisionNGCNode() const {
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::ProvisionNGCNode);
    }

    bool Proxy::RefreshTokenBlob() const {
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::RefreshTokenBlob);
    }

    bool Proxy::ReinitPlugin() const {
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::ReinitPlugin);
    }

    bool Proxy::RenameAccount() const { //xxx
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::RenameAccount);
    }

    bool Proxy::SetTestParas(ULONG TestFlags) const {
        SET_TEST_PARAS_REQUEST request;
        request.Flags = TestFlags;
        void* response{ nullptr };
        auto status{ CallPackage(&request, &response) };
        return status;
    }

    bool Proxy::TransferCreds(PLUID sourceLuid, PLUID destinationLuid) const {
        TRANSFER_CREDS_REQUEST request;
        request.SourceLuid.LowPart = sourceLuid->LowPart;
        request.SourceLuid.HighPart = sourceLuid->HighPart;
        request.DestinationLuid.LowPart = destinationLuid->LowPart;
        request.DestinationLuid.HighPart = destinationLuid->HighPart;
        void* response;
        return CallPackage(request, &response);
    }

    bool Proxy::CallPackage(PROTOCOL_MESSAGE_TYPE MessageType) const {
        auto request{ static_cast<ULONG>(MessageType) };
        void* response{ nullptr };
        return this->CallPackage(request, &response);
    }

    template<typename _Request, typename _Response>
    bool Proxy::CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const {
        if (lsa->Connected()) {
            std::string stringSubmitBuffer(reinterpret_cast<const char*>(&submitBuffer), sizeof(decltype(submitBuffer)));
            return lsa->CallPackage(CLOUDAP_NAME_A, stringSubmitBuffer, reinterpret_cast<void**>(returnBuffer));
        }
        return false;
    }

    bool HandleFunction(std::ostream& out, const Proxy& proxy, const std::string& function, const cxxopts::ParseResult& options) {
        switch (magic_enum::enum_cast<PROTOCOL_MESSAGE_TYPE>(function).value()) {
        case PROTOCOL_MESSAGE_TYPE::ReinitPlugin:
            return proxy.ReinitPlugin();
        case PROTOCOL_MESSAGE_TYPE::GetTokenBlob:
            return proxy.GetTokenBlob(nullptr);
        case PROTOCOL_MESSAGE_TYPE::CallPluginGeneric:
            return false;
        case PROTOCOL_MESSAGE_TYPE::ProfileDeleted:
            return proxy.ProfileDeleted();
        case PROTOCOL_MESSAGE_TYPE::GetAuthenticatingProvider:
            return proxy.GetAuthenticatingProvider(nullptr);
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
                destination.LowPart = options["sluid"].as<DWORD>();
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
        options.allow_unrecognised_options();
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