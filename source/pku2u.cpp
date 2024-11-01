#define _NTDEF_ // Required to include both Ntsecapi and Winternl
#include <Winternl.h>
#include <crypt.hpp>
#include <iomanip>
#include <iostream>
#include <kerberos.hpp>
#include <lsa.hpp>
#include <magic_enum/magic_enum.hpp>
#include <pku2u.hpp>
#include <string>

namespace {
    UNICODE_STRING WCharToUString(wchar_t* string) {
        if (string) {
            auto size{ lstrlenW(string) * sizeof(wchar_t) };
            return { (USHORT)size, (USHORT)((size) ? size + sizeof(wchar_t) : 0), (size) ? string : nullptr };
        }
        return { 0, 0, nullptr };
    }
}

namespace Pku2u {
    Proxy::Proxy(const std::shared_ptr<Lsa>& lsa)
        : lsa(lsa) {
    }

    bool Proxy::PurgeTicketCacheEx(PLUID luid, ULONG flags, const std::wstring& clientName, const std::wstring& clientRealm, const std::wstring& serverName, const std::wstring& serverRealm) const {
        auto requestSize{ sizeof(KERB_PURGE_TKT_CACHE_EX_REQUEST) + ((clientName.length() + clientRealm.length() + serverName.length() + serverRealm.length() + 4) * sizeof(wchar_t)) };
        std::string requestBytes(requestSize, '\0');
        auto request{ reinterpret_cast<PKERB_PURGE_TKT_CACHE_EX_REQUEST>(requestBytes.data()) };
        request->MessageType = static_cast<KERB_PROTOCOL_MESSAGE_TYPE>(PROTOCOL_MESSAGE_TYPE::PurgeTicketCacheEx);
        request->LogonId.LowPart = luid->LowPart;
        request->LogonId.HighPart = luid->HighPart;
        request->Flags = flags;
        request->TicketTemplate = { 0 };
        if (!clientName.empty()) {
            auto ptrUstring{ reinterpret_cast<std::byte*>(request + 1) };
            std::memcpy(ptrUstring, clientName.data(), clientName.size() * sizeof(wchar_t));
            request->TicketTemplate.ClientName = WCharToUString(reinterpret_cast<wchar_t*>(ptrUstring));
        }
        if (!clientRealm.empty()) {
            auto ptrUstring{ reinterpret_cast<std::byte*>(request + 1) + ((clientName.length() + 1) * sizeof(wchar_t)) };
            std::memcpy(ptrUstring, clientRealm.data(), clientRealm.size() * sizeof(wchar_t));
            request->TicketTemplate.ClientRealm = WCharToUString(reinterpret_cast<wchar_t*>(ptrUstring));
        }
        if (!serverName.empty()) {
            auto ptrUstring{ reinterpret_cast<std::byte*>(request + 1) + ((clientName.length() + clientRealm.size() + 2) * sizeof(wchar_t)) };
            std::memcpy(ptrUstring, serverName.data(), serverName.size() * sizeof(wchar_t));
            request->TicketTemplate.ServerName = WCharToUString(reinterpret_cast<wchar_t*>(ptrUstring));
        }
        if (!serverRealm.empty()) {
            auto ptrUstring{ reinterpret_cast<std::byte*>(request + 1) + ((clientName.length() + clientRealm.size() + serverName.size() + 3) * sizeof(wchar_t)) };
            std::memcpy(ptrUstring, serverRealm.data(), serverRealm.size() * sizeof(wchar_t));
            request->TicketTemplate.ServerRealm = WCharToUString(reinterpret_cast<wchar_t*>(ptrUstring));
        }
        void* response{ nullptr };
        return CallPackage(requestBytes, reinterpret_cast<void**>(&response));
    }

    bool Proxy::QueryTicketCacheEx2(PLUID luid) const {
        KERB_QUERY_TKT_CACHE_REQUEST request = { static_cast<KERB_PROTOCOL_MESSAGE_TYPE>(PROTOCOL_MESSAGE_TYPE::QueryTicketCacheEx2) };
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