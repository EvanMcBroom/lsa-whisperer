#define _NTDEF_ // Required to include both Ntsecapi and Winternl
#include <Winternl.h>
#include <crypt.hpp>
#include <iomanip>
#include <iostream>
#include <kerberos.hpp>
#include <lsa.hpp>
#include <magic_enum.hpp>
#include <pku2u.hpp>
#include <string>

namespace Pku2u {
    Proxy::Proxy(const std::shared_ptr<Lsa>& lsa)
        : lsa(lsa) {
    }

    bool Proxy::PurgeTicketEx(PLUID luid, ULONG flags, PKERB_TICKET_CACHE_INFO_EX ticketCacheInfo) const {
        PURGE_TICKET_EX_REQUEST request;
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        request.Flags = flags;
        ticketCacheInfo = ticketCacheInfo;
        KERB_QUERY_TKT_CACHE_EX2_RESPONSE* response{ nullptr };
        auto result{ CallPackage(request, &response) };
        if (result) {
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Proxy::QueryTicketCacheEx2(PLUID luid) const {
        QUERY_TKT_CACHE_EX2_REQUEST request;
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        PKERB_QUERY_TKT_CACHE_EX2_RESPONSE response{ nullptr };
        auto result{ CallPackage(request, &response) };
        std::wcout << std::hex;
        if (result) {
            for (size_t index{ 0 }; index < response->CountOfTickets; index++) {
                auto& ticket{ response->Tickets[index] };
                std::wcout << index << ": " << std::endl;
                std::wcout << "    ClientName    : " << ticket.ClientName.Buffer << std::endl;
                std::wcout << "    ClientRealm   : " << ticket.ClientRealm.Buffer << std::endl;
                std::wcout << "    ServerName    : " << ticket.ServerName.Buffer << std::endl;
                std::wcout << "    ServerRealm   : " << ticket.ServerRealm.Buffer << std::endl;
                std::wcout << "    StartTime     : " << ticket.StartTime.QuadPart << std::endl;
                std::wcout << "    EndTime       : " << ticket.EndTime.QuadPart << std::endl;
                std::wcout << "    RenewTime     : " << ticket.RenewTime.QuadPart << std::endl;
                std::cout  << "    EncryptionType: " << magic_enum::enum_name(static_cast<Kerberos::EncryptionType>(ticket.EncryptionType)) << std::endl;
                std::wcout << "    TicketFlags   : 0x" << std::hex << std::setw(4) << std::setfill(L'0') << ticket.TicketFlags << std::endl;
                std::cout  << "    SessionKeyType: " << magic_enum::enum_name(static_cast<Kerberos::EncryptionType>(ticket.SessionKeyType)) << std::endl;
                std::wcout << "    BranchId      : " << ticket.BranchId << std::endl;
            }
            LsaFreeReturnBuffer(response);
        }
        return result;
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