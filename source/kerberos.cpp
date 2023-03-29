#define _NTDEF_ // Required to include both Ntsecapi and Winternl
#include <Winternl.h>
#include <iostream>
#include <lsa.hpp>
#include <string>
#include <cxxopts.hpp>
#include <codecvt>
#include <crypt.hpp>
#include <magic_enum.hpp>
#include <kerberos.hpp>

namespace Kerberos {
    Proxy::Proxy(const std::shared_ptr<Lsa>& lsa)
        : lsa(lsa) {
    }

    bool Proxy::QueryTicketCache(PLUID luid) const {
        QUERY_TKT_CACHE_REQUEST request;
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        void* response{ nullptr };
        auto result{ CallPackage(request, &response) };
        if (result) {
            LsaFreeReturnBuffer(response);
        }
        return result;
    }
    template<typename _Request, typename _Response>
    bool Proxy::CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const {
        if (lsa->Connected()) {
            std::string stringSubmitBuffer(reinterpret_cast<const char*>(&submitBuffer), sizeof(decltype(submitBuffer)));
            return lsa->CallPackage(MICROSOFT_KERBEROS_NAME_A, stringSubmitBuffer, reinterpret_cast<void**>(returnBuffer));
        }
        return false;
    }

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
        options.add_options("Function arguments")
            ("luid", "Logon session", cxxopts::value<long long>());

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