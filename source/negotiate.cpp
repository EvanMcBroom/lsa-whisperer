#define _NTDEF_ // Required to include both Ntsecapi and Winternl
#include <Winternl.h>
#include <crypt.hpp>
#include <cxxopts.hpp>
#include <lsa.hpp>
#include <magic_enum.hpp>
#include <negotiate.hpp>
#include <string>
#include <security.h>

namespace Negotiate {
    Proxy::Proxy(const std::shared_ptr<Lsa>& lsa)
        : lsa(lsa) {
    }
    
    bool Proxy::EnumPackageNames() const {
        void* response;
        auto result{ this->CallPackage(PROTOCOL_MESSAGE_TYPE::EnumPackageNames, &response) };
        if (result) {
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Proxy::EnumPackagePrefixes() const {
        PPACKAGE_PREFIXES response;
        auto result{ this->CallPackage(PROTOCOL_MESSAGE_TYPE::EnumPackagePrefixes, &response) };
        if (result) {
            lsa->out << "PrefixCount: " << response->PrefixCount << std::endl;
            auto offset{ reinterpret_cast<byte*>(response) + response->Offset };
            for (size_t count{ response->PrefixCount }; count > 0; count--) {
                auto packagePrefix{ reinterpret_cast<PPACKAGE_PREFIX>(offset) };
                lsa->out << std::to_string(packagePrefix->PackageId) + " Prefix[0x" << packagePrefix->PrefixLen << "]: ";
                OutputHex(lsa->out, std::string(reinterpret_cast<char*>(packagePrefix->Prefix), MaxPrefix()));
                lsa->out << std::endl;
                offset += sizeof(PACKAGE_PREFIX);
            }
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Proxy::GetCallerName(PLUID luid) const {
        CALLER_NAME_REQUEST request;
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        PCALLER_NAME_RESPONSE response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            std::wcout << "CallerName: " << response->CallerName << std::endl;
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    template<typename _Request, typename _Response>
    bool Proxy::CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const {
        if (lsa->Connected()) {
            std::string stringSubmitBuffer(reinterpret_cast<const char*>(&submitBuffer), sizeof(decltype(submitBuffer)));
            return lsa->CallPackage(NEGOSSP_NAME_A, stringSubmitBuffer, reinterpret_cast<void**>(returnBuffer));
        }
        return false;
    }

    bool HandleFunction(std::ostream& out, const Proxy& proxy, const std::string& function, const cxxopts::ParseResult& options) {
        switch (magic_enum::enum_cast<PROTOCOL_MESSAGE_TYPE>(function).value()) {
        case PROTOCOL_MESSAGE_TYPE::EnumPackagePrefixes:
            return proxy.EnumPackagePrefixes();
        case PROTOCOL_MESSAGE_TYPE::GetCallerName: {
            LUID luid;
            reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = options["luid"].as<long long>();
            return proxy.GetCallerName(&luid);
        }
        case PROTOCOL_MESSAGE_TYPE::EnumPackageNames:
            return proxy.EnumPackageNames();
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