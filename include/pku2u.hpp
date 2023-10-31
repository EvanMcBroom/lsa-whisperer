#pragma once
#include <pch.hpp>

#include <lsa.hpp>

#define PKU2U_NAME_A "pku2u"

namespace Pku2u {
    enum class PROTOCOL_MESSAGE_TYPE : ULONG {
        PurgeTicketEx = 0x0F,
        QueryTicketCacheEx2 = 0x14,
    };
    
    typedef struct _PURGE_TICKET_EX_REQUEST : KERB_PURGE_TKT_CACHE_EX_REQUEST {
        _PURGE_TICKET_EX_REQUEST() {
            MessageType = static_cast<KERB_PROTOCOL_MESSAGE_TYPE>(PROTOCOL_MESSAGE_TYPE::PurgeTicketEx);
        }
    } PURGE_TICKET_EX_REQUEST, *PPURGE_TICKET_EX_REQUEST;

    typedef struct _QUERY_TKT_CACHE_EX2_REQUEST : KERB_QUERY_TKT_CACHE_REQUEST {
        _QUERY_TKT_CACHE_EX2_REQUEST() {
            MessageType = static_cast<KERB_PROTOCOL_MESSAGE_TYPE>(PROTOCOL_MESSAGE_TYPE::QueryTicketCacheEx2);
        }
    } QUERY_TKT_CACHE_EX2_REQUEST, *PQUERY_TKT_CACHE_EX2_REQUEST;

    class Proxy {
    public:
        Proxy(const std::shared_ptr<Lsa>& lsa);

        bool PurgeTicketEx(PLUID luid, ULONG flags, PKERB_TICKET_CACHE_INFO_EX ticketCacheInfo = nullptr) const;
        bool QueryTicketCacheEx2(PLUID luid) const;

    protected:
        std::shared_ptr<Lsa> lsa;

    private:
        // You must free all returnBuffer outputs with LsaFreeReturnBuffer
        template<typename _Request, typename _Response>
        bool CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const;
    };
}