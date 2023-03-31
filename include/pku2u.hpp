#pragma once
#include <Winternl.h>
#include <lsa.hpp>

#define PKU2U_NAME_A "pku2u"

namespace Pku2u {
    enum class PROTOCOL_MESSAGE_TYPE : ULONG {
        PurgeTicketEx = 0x0F,
        QueryTicketCacheEx2 = 0x14,
    };

    typedef struct _PURGE_TICKET_EX_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::PurgeTicketEx };
        // unknown
    } PURGE_TICKET_EX_REQUEST, *PPURGE_TICKET_EX_REQUEST;

    typedef struct _PURGE_TICKET_EX_RESPONSE {
        PROTOCOL_MESSAGE_TYPE MessageType;
        // unknown
    } PURGE_TICKET_EX_RESPONSE, *PPURGE_TICKET_EX_RESPONSE;

    typedef struct _QUERY_TICKET_CACHE_EX2_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::QueryTicketCacheEx2 };
        LUID LogonId;
    } QUERY_TICKET_CACHE_EX2_REQUEST, *PQUERY_TICKET_CACHE_EX2_REQUEST;

    typedef struct _QUERY_TICKET_CACHE_EX2_RESPONSE {
        PROTOCOL_MESSAGE_TYPE MessageType;
        // unknown
    } QUERY_TICKET_CACHE_EX2_RESPONSE, *PQUERY_TICKET_CACHE_EX2_RESPONSE;

    class Proxy {
    public:
        Proxy(const std::shared_ptr<Lsa>& lsa);

        // A subset of the supported functions in pku2u
        bool PurgeTicketEx() const;
        bool QueryTicketCacheEx2(PLUID luid) const;

    protected:
        std::shared_ptr<Lsa> lsa;

    private:
        // You must free all returnBuffer outputs with LsaFreeReturnBuffer
        template<typename _Request, typename _Response>
        bool CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const;
    };
}