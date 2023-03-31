#define _NTDEF_ // Required to include both Ntsecapi and Winternl
#include <Winternl.h>
#include <crypt.hpp>
#include <lsa.hpp>
#include <msv1_0.hpp>
#include <negotiate.hpp>
#include <security.h>
#include <string>

namespace Negotiate {
    Proxy::Proxy(const std::shared_ptr<Lsa>& lsa)
        : lsa(lsa) {
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
                OutputHex(lsa->out, std::string(reinterpret_cast<char*>(packagePrefix->Prefix), packagePrefix->PrefixLen));
                lsa->out << std::endl
                         << "         Leak: ";
                OutputHex(lsa->out, std::string(reinterpret_cast<char*>(packagePrefix->Prefix) + packagePrefix->PrefixLen, MaxPrefix() - packagePrefix->PrefixLen));
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
            std::wcout << "CallerName [" << response->CallerName << "]: " << std::wstring{ reinterpret_cast<PWSTR>(response + 1) } << std::endl;
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
}