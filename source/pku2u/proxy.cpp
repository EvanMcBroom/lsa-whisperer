#define _NTDEF_ // Required to include both Ntsecapi and Winternl
#include <Winternl.h>
#include <iostream>
#include <lsa.hpp>
#include <string>
#include <pku2u/messages.hpp>
#include <pku2u/proxy.hpp>

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
}