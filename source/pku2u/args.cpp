#include <cxxopts.hpp>
#include <codecvt>
#include <crypt.hpp>
#include <magic_enum.hpp>
#include <pku2u/args.hpp>
#include <pku2u/messages.hpp>
#include <pku2u/proxy.hpp>

namespace Pku2u {
    bool HandleFunction(const Proxy& proxy, const cxxopts::ParseResult& result) {
        switch (magic_enum::enum_cast<PROTOCOL_MESSAGE_TYPE>(result["function"].as<std::string>()).value()) {
        case PROTOCOL_MESSAGE_TYPE::PurgeTicketEx:
            return proxy.PurgeTicketEx();
        case PROTOCOL_MESSAGE_TYPE::QueryTicketCacheEx2: {
            LUID luid;
            reinterpret_cast<LARGE_INTEGER*>(&luid)->QuadPart = result["luid"].as<long long>();
            return proxy.QueryTicketCacheEx2(&luid);
        }
        default:
            std::cout << "Unsupported function" << std::endl;
            return false;
        }
    }

    bool Parse(int argc, char** argv) {
        cxxopts::Options options{ "pku2u-cli", "A CLI for the pku2u authentication package" };

        options.add_options("Pku2u Function")
            ("f,function", "Function name", cxxopts::value<std::string>())
            ;

        // Arguments for functions that require additional inputs
        options.add_options("Function arguments")
            ("luid", "Logon session", cxxopts::value<long long>())
            ;

        try {
            auto result{ options.parse(argc, argv) };
            if (result.count("function")) {
                auto lsa{ std::make_shared<Lsa>() };
                Proxy proxy{ lsa };
                return HandleFunction(proxy, result);
            }
            else {
                std::cout << options.help() << std::endl;
                return false;
            }
        }
        catch (const std::exception& exception) {
            std::cout << exception.what() << std::endl;
        }
    }
}