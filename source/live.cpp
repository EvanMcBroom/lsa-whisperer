#define _NTDEF_ // Required to include both Ntsecapi and Winternl
#include <Winternl.h>
#include <crypt.hpp>
#include <iomanip>
#include <iostream>
#include <kerberos.hpp>
#include <lsa.hpp>
#include <magic_enum/magic_enum.hpp>
#include <live.hpp>
#include <string>

namespace Live {
    Proxy::Proxy(const std::shared_ptr<Lsa>& lsa)
        : lsa(lsa) {
    }

    bool Proxy::GetSignedProofOfPossessionToken() const {
        return CallPackage(PROTOCOL_MESSAGE_TYPE::GetSignedProofOfPossessionToken);
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
            return lsa->CallPackage(LIVE_NAME_A, stringSubmitBuffer, reinterpret_cast<void**>(returnBuffer));
        }
        return false;
    }
}