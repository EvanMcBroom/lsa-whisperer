#pragma once
#include <pch.hpp>

#include <lsa.hpp>

#define PKU2U_NAME_A "pku2u"

namespace Pku2u {
    enum class PROTOCOL_MESSAGE_TYPE : ULONG {
        PurgeTicketCacheEx = 0x0F,
        QueryTicketCacheEx2 = 0x14,
    };

    class Proxy {
    public:
        Proxy(const std::shared_ptr<Lsa>& lsa);

        bool PurgeTicketCacheEx(PLUID luid, ULONG flags, const std::wstring& clientName, const std::wstring& clientRealm, const std::wstring& serverName, const std::wstring& serverRealm) const;
        bool QueryTicketCacheEx2(PLUID luid) const;

    protected:
        std::shared_ptr<Lsa> lsa;

    private:
        // You must free all returnBuffer outputs with LsaFreeReturnBuffer
        template<typename _Request, typename _Response>
        bool CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const;
    };
}