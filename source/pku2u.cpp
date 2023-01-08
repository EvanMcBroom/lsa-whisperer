#define _NTDEF_ // Required to include both Ntsecapi and Winternl
#include <Winternl.h>
#include <iostream>
#include <lsa.hpp>
#include <string>
#include <cxxopts.hpp>
#include <codecvt>
#include <crypt.hpp>
#include <magic_enum.hpp>
#include <pku2u.hpp>

namespace Pku2u {
    bool Proxy::PurgeTicketEx() const {
        return false;
    }

    bool Proxy::QueryTicketCacheEx2(PLUID luid) const {
        QUERY_TICKET_CACHE_EX2_REQUEST request;
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        void* response;
        return CallPackage(request, &response);
    }

    template<typename _Request, typename _Response>
    bool Proxy::CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const {
        if (lsa->Connected()) {
            std::string stringSubmitBuffer(reinterpret_cast<const char*>(&submitBuffer), sizeof(decltype(submitBuffer)));
            return lsa->CallPackage(PKU2U_NAME_A, stringSubmitBuffer, reinterpret_cast<void**>(returnBuffer));
        }
        return false;
    }
    
    bool HandleFunction(std::ostream& out, const Proxy& proxy, const cxxopts::ParseResult& result) {
        switch (magic_enum::enum_cast<PROTOCOL_MESSAGE_TYPE>(result["function"].as<std::string>()).value()) {
        case PROTOCOL_MESSAGE_TYPE::PurgeTicketEx:
            return proxy.PurgeTicketEx();
        case PROTOCOL_MESSAGE_TYPE::QueryTicketCacheEx2: {
            LUID luid;
            reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = result["luid"].as<long long>();
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

        options.add_options("Pku2u Function")
            ("f,function", "Function name", cxxopts::value<std::string>())
            ;

        // Arguments for functions that require additional inputs
        options.add_options("Function arguments")
            ("luid", "Logon session", cxxopts::value<long long>())
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