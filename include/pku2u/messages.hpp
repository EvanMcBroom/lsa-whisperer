#pragma once
#include <Winternl.h>

namespace Pku2u {
    enum class PROTOCOL_MESSAGE_TYPE : ULONG {
        PurgeTicketEx = 0x0F,
        QueryTicketCacheEx2 = 0x14,
    };

    typedef struct _PURGE_TICKET_EX_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::PurgeTicketEx };
        // unknown
    } PURGE_TICKET_EX_REQUEST, * PPURGE_TICKET_EX_REQUEST;

    typedef struct _PURGE_TICKET_EX_RESPONSE {
        PROTOCOL_MESSAGE_TYPE MessageType;
        // unknown
    } PURGE_TICKET_EX_RESPONSE, * PPURGE_TICKET_EX_RESPONSE;

    typedef struct _QUERY_TICKET_CACHE_EX2_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::QueryTicketCacheEx2 };
        LUID LogonId;
    } QUERY_TICKET_CACHE_EX2_REQUEST, * PQUERY_TICKET_CACHE_EX2_REQUEST;

    typedef struct _QUERY_TICKET_CACHE_EX2_RESPONSE {
        PROTOCOL_MESSAGE_TYPE MessageType;
        // unknown
    } QUERY_TICKET_CACHE_EX2_RESPONSE, * PQUERY_TICKET_CACHE_EX2_RESPONSE;
}