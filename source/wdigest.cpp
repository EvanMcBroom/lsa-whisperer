#define _NTDEF_ // Required to include both Ntsecapi and Winternl
#include <Winternl.h>
#include <codecvt>
#include <crypt.hpp>
#include <cxxopts.hpp>
#include <iostream>
#include <lsa.hpp>
#include <magic_enum.hpp>
#include <schannel.hpp>
#include <string>
#include <vector>
#include <wdigest.h>
#include <wdigest.hpp>

namespace Wdigest {
    Proxy::Proxy(const std::shared_ptr<Lsa>& lsa)
        : lsa(lsa) {
    }

    bool Proxy::VerifyDigest() const {
        VERIFY_DIGEST_REQUEST request;
        VERIFY_DIGEST_RESPONSE* response;
        return CallPackagePassthrough(request, &response);
    }

    template<typename _Request, typename _Response>
    bool Proxy::CallPackagePassthrough(const _Request& submitBuffer, _Response** returnBuffer) const {
        if (lsa->Connected()) {
            std::string stringSubmitBuffer(reinterpret_cast<const char*>(&submitBuffer), sizeof(decltype(submitBuffer)));
            return lsa->CallPackage(WDIGEST_SP_NAME_A, stringSubmitBuffer, reinterpret_cast<void**>(returnBuffer));
        }
        return false;
    }

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