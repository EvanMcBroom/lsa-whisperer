#define _NTDEF_ // Required to include both Ntsecapi and Winternl
#include <Winternl.h>
#include <codecvt>
#include <crypt.hpp>
#include <iostream>
#include <kerberos.hpp>
#include <lsa.hpp>
#include <string>
#include <iomanip>
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
  
    bool Proxy::ChangeMachinePassword(const std::wstring& oldPassword, const std::wstring& newPassword) const {
        CHANGE_MACH_PWD_REQUEST request;
        RtlInitUnicodeString(&request.OldPassword, oldPassword.data());
        RtlInitUnicodeString(&request.NewPassword, newPassword.data());

        void* response{ nullptr };
        auto result{ CallPackage(request, &response) };
        return result;
    }

    bool Proxy::RetrieveEncodedTicket(PLUID luid, const std::wstring& targetName, TicketFlags flags, CacheOptions options, EncryptionType type) const {
        std::vector<byte> requestBytes(sizeof(RETRIEVE_TKT_REQUEST) + (targetName.size() * sizeof(wchar_t) + 2), 0);
        auto request{ reinterpret_cast<PRETRIEVE_TKT_REQUEST>(requestBytes.data()) };
        request->MessageType = PROTOCOL_MESSAGE_TYPE::RetrieveEncodedTicket;
        request->LogonId.LowPart = luid->LowPart;
        request->LogonId.HighPart = luid->HighPart;
        request->TargetName.Length = targetName.size() * sizeof(wchar_t);
        request->TargetName.MaximumLength = request->TargetName.Length + 2;
        auto buffer{ reinterpret_cast<wchar_t*>(request + 1) };
        std::memcpy(buffer, targetName.data(), request->TargetName.MaximumLength);
        request->TicketFlags = static_cast<ULONG>(flags);
        request->CacheOptions = static_cast<ULONG>(options);
        request->EncryptionType = static_cast<ULONG>(type);
        RETRIEVE_TKT_RESPONSE* response{ nullptr };
        // patching the targetname.buffer pointer address...
        std::string stringSubmitBuffer(requestBytes.begin(), requestBytes.end());

        auto requestTemplate{
            reinterpret_cast<PRETRIEVE_TKT_REQUEST>(stringSubmitBuffer.data())
        };

        requestTemplate->TargetName.Buffer = reinterpret_cast<wchar_t*>(stringSubmitBuffer.data() + sizeof(RETRIEVE_TKT_REQUEST));
        auto result{ CallPackage(stringSubmitBuffer, &response) };
        if (result) {
            auto& ticket{ response->Ticket };
            printf("Service name    : %ws \n", ticket.ServiceName->Names[0].Buffer);
            printf("TargetName name : %ws \n", ticket.TargetName->Names[0].Buffer);
            printf("ClientName name : %ws \n", ticket.ClientName->Names[0].Buffer);
            std::wcout << "SessionKey.KeyType  : " << ticket.SessionKey.KeyType << std::endl;
            std::wcout << "SessionKey.Value : ";

            for (ULONG i = 0; i < ticket.SessionKey.Length; ++i) {
                std::cout << std::hex << std::setfill('0') << static_cast<int>(ticket.SessionKey.Value[i]);
            }
            std::wcout << std::endl;
            std::wcout << "TicketFlags         : " << ticket.TicketFlags << std::endl;
            std::wcout << "Flags               : " << ticket.Flags << std::endl;
            std::wcout << "KeyExpirationTime   : " << ticket.KeyExpirationTime.QuadPart << std::endl;
            std::wcout << "StartTime           : " << ticket.StartTime.QuadPart << std::endl;
            std::wcout << "EndTime             : " << ticket.EndTime.QuadPart << std::endl;
            std::wcout << "RenewUntil          : " << ticket.RenewUntil.QuadPart << std::endl;
            std::wcout << "TimeSkew            : " << ticket.TimeSkew.QuadPart << std::endl;
            std::wcout << "EncodedTicket       : ";
            for (ULONG i = 0; i < ticket.EncodedTicketSize; ++i) {
                std::cout << std::hex << std::setfill('0') << static_cast<int>(ticket.EncodedTicket[i]);
            }
            //HexDecode(std::cout, std::wstring{ ticket.EncodedTicket, ticket.EncodedTicket + ticket.EncodedTicketSize });
            std::wcout << std::endl;
            LsaFreeReturnBuffer(response);
            return result;
        }
    }

    bool Proxy::TransferCreds(PLUID sourceLuid, PLUID destinationLuid, ULONG flags) const {
        TRANSFER_CRED_REQUEST request;
        request.OriginLogonId.LowPart = sourceLuid->LowPart;
        request.OriginLogonId.HighPart = sourceLuid->HighPart;
        request.DestinationLogonId.LowPart = destinationLuid->LowPart;
        request.DestinationLogonId.HighPart = destinationLuid->HighPart;
        request.Flags = flags;
        void* response;
        return CallPackage(request, &response);
    }
  
    template<typename _Request, typename _Response>
    bool Proxy::CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const {
        if (lsa->Connected()) {
            return lsa->CallPackage(MICROSOFT_KERBEROS_NAME_A, submitBuffer, reinterpret_cast<void**>(returnBuffer));
        }
        return false;
    }

    bool Proxy::CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const {
        std::string stringSubmitBuffer(reinterpret_cast<const char*>(&submitBuffer), sizeof(decltype(submitBuffer)));
        return CallPackage(submitBuffer, reinterpret_cast<void**>(returnBuffer));
    }

    template<typename _Request, typename _Response>
    bool Proxy::CallPackage(_Request* submitBuffer, size_t submitBufferLength, _Response** returnBuffer) const {
        std::string stringSubmitBuffer(reinterpret_cast<const char*>(submitBuffer), submitBufferLength);
        std::cout << "The address of stringSubmitBuffer is: " << static_cast<void*>(&stringSubmitBuffer[0]) << std::endl;
        return CallPackage(stringSubmitBuffer, reinterpret_cast<void**>(returnBuffer));
    }
}