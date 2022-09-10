#define _NTDEF_ // Required to include both Ntsecapi and Winternl
#include <Winternl.h>
#include <iostream>
#include <lsa.hpp>
#include <string>
#include <pku2u/messages.hpp>
#include <pku2u/stubs.hpp>

#define STATUS_SUCCESS 0

namespace Pku2u {
    template<typename _Request, typename _Response>
    bool CallPackage(const _Request& submitBuffer, _Response** returnBuffer) {
        std::string stringSubmitBuffer(reinterpret_cast<const char*>(&submitBuffer), sizeof(decltype(submitBuffer)));
        return ::CallPackage(PKU2U_NAME_A, stringSubmitBuffer, reinterpret_cast<void**>(returnBuffer));
    }

    bool PurgeTicketEx() {
        return false;
    }

    bool QueryTicketCacheEx2(PLUID luid) {
        QUERY_TICKET_CACHE_EX2_REQUEST request;
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        void* response;
        return CallPackage(request, &response);
    }
}