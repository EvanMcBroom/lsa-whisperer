#define _NTDEF_ // Required to include both Ntsecapi and Winternl
#include <Winternl.h>
#include <codecvt>
#include <crypt.hpp>
#include <iostream>
#include <kerberos.hpp>
#include <lsa.hpp>
#include <string>

namespace Kerberos {
    Proxy::Proxy(const std::shared_ptr<Lsa>& lsa)
        : lsa(lsa) {
    }

    bool Proxy::QueryTicketCache(PLUID luid) const {
        QUERY_TKT_CACHE_REQUEST request;
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        void* response{ nullptr };
        auto result{ CallPackage(request, &response) };
        if (result) {
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Proxy::RetrieveEncodedTicket(PLUID luid, const std::wstring& targetName, TicketFlags flags, CacheOptions options, EncryptionType type) const {
        std::vector<byte> requestBytes(sizeof(RETRIEVE_TKT_REQUEST) + (targetName.size() * sizeof(wchar_t)), 0);
        auto request{ reinterpret_cast<PRETRIEVE_TKT_REQUEST>(requestBytes.data()) };
        request->MessageType = PROTOCOL_MESSAGE_TYPE::RetrieveEncodedTicket;
        request->LogonId.LowPart = luid->LowPart;
        request->LogonId.HighPart = luid->HighPart;
        request->TargetName.Length = targetName.size() * sizeof(wchar_t);
        request->TargetName.MaximumLength = request->TargetName.Length;
        auto buffer{ reinterpret_cast<wchar_t*>(request + 1) };
        std::memcpy(buffer, targetName.data(), targetName.length() * sizeof(wchar_t));
        request->TargetName.Buffer = buffer;
        request->TicketFlags = static_cast<ULONG>(flags);
        request->CacheOptions = static_cast<ULONG>(options);
        request->EncryptionType = static_cast<ULONG>(type);
        RETRIEVE_TKT_RESPONSE* response{ nullptr };
        auto result{ CallPackage(requestBytes.data(), requestBytes.size(), &response) };
        if (result) {
            auto& ticket{ response->Ticket };
            std::wcout << "ServiceName         : " << ticket.ServiceName << std::endl;
            std::wcout << "TargetName          : " << ticket.TargetName << std::endl;
            std::wcout << "ClientName          : " << ticket.ClientName << std::endl;
            std::wcout << "DomainName          : " << ticket.DomainName.Buffer << std::endl;
            std::wcout << "TargetDomainName    : " << ticket.TargetDomainName.Buffer << std::endl;
            std::wcout << "AltTargetDomainName : " << ticket.AltTargetDomainName.Buffer << std::endl;
            std::wcout << "SessionKey.KeyType  : " << ticket.SessionKey.KeyType << std::endl;
            std::wcout << "SessionKey.Value    : ";
            HexDecode(std::cout, std::wstring{ ticket.SessionKey.Value, ticket.SessionKey.Value + ticket.SessionKey.Length });
            std::wcout << std::endl;
            std::wcout << "TicketFlags         : " << ticket.TicketFlags << std::endl;
            std::wcout << "Flags               : " << ticket.Flags << std::endl;
            std::wcout << "KeyExpirationTime   : " << ticket.KeyExpirationTime.QuadPart << std::endl;
            std::wcout << "StartTime           : " << ticket.StartTime.QuadPart << std::endl;
            std::wcout << "EndTime             : " << ticket.EndTime.QuadPart << std::endl;
            std::wcout << "RenewUntil          : " << ticket.RenewUntil.QuadPart << std::endl;
            std::wcout << "TimeSkew            : " << ticket.TimeSkew.QuadPart << std::endl;
            std::wcout << "EncodedTicket       : ";
            HexDecode(std::cout, std::wstring{ ticket.EncodedTicket, ticket.EncodedTicket + ticket.EncodedTicketSize });
            std::wcout << std::endl;
            LsaFreeReturnBuffer(response);
        }
    }

    template<typename _Request, typename _Response>
    bool Proxy::CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const {
        if (lsa->Connected()) {
            std::string stringSubmitBuffer(reinterpret_cast<const char*>(&submitBuffer), sizeof(decltype(submitBuffer)));
            return lsa->CallPackage(MICROSOFT_KERBEROS_NAME_A, stringSubmitBuffer, reinterpret_cast<void**>(returnBuffer));
        }
        return false;
    }
}