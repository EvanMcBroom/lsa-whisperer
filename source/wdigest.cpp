#define _NTDEF_ // Required to include both Ntsecapi and Winternl
#include <Winternl.h>
#include <codecvt>
#include <crypt.hpp>
#include <iostream>
#include <lsa.hpp>
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
}