#pragma once
#include <lsa.hpp>

#define PKU2U_NAME_A "pku2u"

namespace Pku2u {
    class Proxy : public SspiProxy {
    public:
        // A subset of the supported functions in pku2u
        bool PurgeTicketEx() const;
        bool QueryTicketCacheEx2(PLUID luid) const;

    private:
        // You must free all returnBuffer outputs with LsaFreeReturnBuffer
        template<typename _Request, typename _Response>
        bool CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const;
    };
}