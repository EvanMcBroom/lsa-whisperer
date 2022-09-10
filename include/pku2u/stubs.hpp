#pragma once
#include <lsa.hpp>

#define PKU2U_NAME_A "pku2u"

namespace Pku2u {
    template<typename _Request, typename _Response>
    bool CallPackage(const _Request& submitBuffer, _Response** returnBuffer);

    bool PurgeTicketEx();
    bool QueryTicketCacheEx2(PLUID luid);
}