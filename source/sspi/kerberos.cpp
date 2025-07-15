// Copyright (C) 2025 Evan McBroom
#include "sspi/kerberos.hpp"
#include "sspi/crypt.hpp"
#include <codecvt>
#include <iomanip>
#include <iostream>
#include <string>

namespace {
    UNICODE_STRING WCharToUString(wchar_t* string) {
        if (string) {
            auto size{ lstrlenW(string) * sizeof(wchar_t) };
            return { (USHORT)size, (USHORT)((size) ? size + sizeof(wchar_t) : 0), (size) ? string : nullptr };
        }
        return { 0, 0, nullptr };
    }

    UNICODE_STRING WStringToUString(const std::wstring& string) {
        if (!string.empty()) {
            auto size{ string.size() * sizeof(wchar_t) };
            return { (USHORT)size, (USHORT)(size + sizeof(wchar_t)), const_cast<wchar_t*>(string.data()) };
        }
        return { 0, 0, nullptr };
    }
}

namespace Kerberos {
    Api::Api(const std::shared_ptr<Lsa::Api>& lsa)
        : lsa(lsa) {
    }

    bool Api::AddBindingCacheEntry(const std::wstring& realmName, const std::wstring& kdcAddress, ULONG addressType) const {
        return AddBindingCacheEntryEx(realmName, kdcAddress, addressType, 0, false);
    }

    bool Api::AddBindingCacheEntryEx(const std::wstring& realmName, const std::wstring& kdcAddress, ULONG addressType, ULONG dcFlags, bool useEx) const {
        // We can use the EX version of the struct for both message types because it's only an extension of the original struct format
        auto requestSize{ sizeof(KERB_ADD_BINDING_CACHE_ENTRY_EX_REQUEST) + ((realmName.length() + kdcAddress.length() + 2) * sizeof(wchar_t)) };
        std::string requestBytes(requestSize, '\0');
        auto request{ reinterpret_cast<PKERB_ADD_BINDING_CACHE_ENTRY_EX_REQUEST>(requestBytes.data()) };
        if (useEx) {
            request->MessageType = KERB_PROTOCOL_MESSAGE_TYPE::KerbAddBindingCacheEntryExMessage;
            request->DcFlags = dcFlags;
        } else {
            request->MessageType = KERB_PROTOCOL_MESSAGE_TYPE::KerbAddBindingCacheEntryMessage;
        }
        request->AddressType = addressType;

        auto ptrUstring{ reinterpret_cast<std::byte*>(request + 1) };
        std::memcpy(ptrUstring, realmName.data(), realmName.size() * sizeof(wchar_t));
        request->RealmName = WCharToUString(reinterpret_cast<wchar_t*>(ptrUstring));

        ptrUstring = ptrUstring + ((realmName.length() + 1) * sizeof(wchar_t));
        std::memcpy(ptrUstring, kdcAddress.data(), kdcAddress.size() * sizeof(wchar_t));
        request->KdcAddress = WCharToUString(reinterpret_cast<wchar_t*>(ptrUstring));

        void* response{ nullptr };
        return CallPackage(requestBytes, reinterpret_cast<void**>(&response));
    }

    bool Api::AddExtraCredentials(PLUID luid, const std::wstring& domainName, const std::wstring& userName, const std::wstring& password, ULONG flags) const {
        auto requestSize{ sizeof(KERB_ADD_CREDENTIALS_REQUEST) + ((domainName.length() + userName.length() + password.length() + 3) * sizeof(wchar_t)) };
        std::string requestBytes(requestSize, '\0');
        auto request{ reinterpret_cast<PKERB_ADD_CREDENTIALS_REQUEST>(requestBytes.data()) };
        request->MessageType = KERB_PROTOCOL_MESSAGE_TYPE::KerbAddExtraCredentialsMessage;
        request->LogonId.LowPart = luid->LowPart;
        request->LogonId.HighPart = luid->HighPart;
        request->Flags = flags;

        auto ptrUstring{ reinterpret_cast<std::byte*>(request + 1) };
        std::memcpy(ptrUstring, domainName.data(), domainName.size() * sizeof(wchar_t));
        request->DomainName = WCharToUString(reinterpret_cast<wchar_t*>(ptrUstring));

        ptrUstring = ptrUstring + ((domainName.length() + 1) * sizeof(wchar_t));
        std::memcpy(ptrUstring, userName.data(), userName.size() * sizeof(wchar_t));
        request->UserName = WCharToUString(reinterpret_cast<wchar_t*>(ptrUstring));

        ptrUstring = ptrUstring + ((userName.length() + 1) * sizeof(wchar_t));
        std::memcpy(ptrUstring, password.data(), password.size() * sizeof(wchar_t));
        request->Password = WCharToUString(reinterpret_cast<wchar_t*>(ptrUstring));

        void* response{ nullptr };
        return CallPackage(requestBytes, reinterpret_cast<void**>(&response));
    }

    bool Api::CleanupMachinePkinitCreds(PLUID luid) const {
        KERB_CLEANUP_MACHINE_PKINIT_CREDS_REQUEST request = { KERB_PROTOCOL_MESSAGE_TYPE::KerbCleanupMachinePkinitCredsMessage };
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        void* response{ nullptr };
        return CallPackage(request, &response);
    }

    bool Api::PinKdc(const std::wstring& domainName, const std::wstring& dcName, ULONG dcFlags) const {
        auto requestSize{ sizeof(SECPKG_CALL_PACKAGE_PIN_DC_REQUEST) + ((domainName.length() + dcName.length() + 2) * sizeof(wchar_t)) };
        std::string requestBytes(requestSize, '\0');
        auto request{ reinterpret_cast<PSECPKG_CALL_PACKAGE_PIN_DC_REQUEST>(requestBytes.data()) };
        request->MessageType = KERB_PROTOCOL_MESSAGE_TYPE::KerbPinKdcMessage;
        request->Flags = 0; // Ignored
        request->DcFlags = dcFlags;

        auto ptrUstring{ reinterpret_cast<std::byte*>(request + 1) };
        std::memcpy(ptrUstring, domainName.data(), domainName.size() * sizeof(wchar_t));
        request->DomainName = WCharToUString(reinterpret_cast<wchar_t*>(ptrUstring));

        ptrUstring = ptrUstring + ((domainName.length() + 1) * sizeof(wchar_t));
        std::memcpy(ptrUstring, dcName.data(), dcName.size() * sizeof(wchar_t));
        request->DcName = WCharToUString(reinterpret_cast<wchar_t*>(ptrUstring));

        void* response{ nullptr };
        return CallPackage(requestBytes, reinterpret_cast<void**>(&response));
    }

    bool Api::PrintCloudKerberosDebug(PLUID luid) const {
        KERB_CLOUD_KERBEROS_DEBUG_REQUEST request = { KERB_PROTOCOL_MESSAGE_TYPE::KerbPrintCloudKerberosDebugMessage };
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        PKERB_CLOUD_KERBEROS_DEBUG_RESPONSE response{ nullptr };
        auto result{ CallPackage(request, &response) };
        if (result) {
            std::wcout << "Version: " << response->Version << std::endl;
            auto version0{ reinterpret_cast<PKERB_CLOUD_KERBEROS_DEBUG_DATA_V0>(&response->Data) };
            std::wcout << "EnabledByPolicy          : " << version0->EnabledByPolicy << std::endl;
            std::wcout << "AsRepCallbackPresent     : " << version0->AsRepCallbackPresent << std::endl;
            std::wcout << "AsRepCallbackUsed        : " << version0->AsRepCallbackUsed << std::endl;
            std::wcout << "CloudReferralTgtAvailable: " << version0->CloudReferralTgtAvailable << std::endl;
            std::wcout << "SpnOracleConfigured      : " << version0->SpnOracleConfigured << std::endl;
            std::wcout << "KdcProxyPresent          : " << version0->KdcProxyPresent << std::endl;
            if (response->Version >= 1) {
                auto version1{ reinterpret_cast<PKERB_CLOUD_KERBEROS_DEBUG_DATA>(&response->Data) };
                std::wcout << "PublicKeyCredsPresent    : " << version1->PublicKeyCredsPresent << std::endl;
                std::wcout << "PasswordKeysPresent      : " << version1->PasswordKeysPresent << std::endl;
                std::wcout << "PasswordPresent          : " << version1->PasswordPresent << std::endl;
                std::wcout << "AsRepSourceCred          : " << version1->AsRepSourceCred << std::endl;
            }
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::PurgeBindingCache() const {
        KERB_PURGE_BINDING_CACHE_REQUEST request{ KERB_PROTOCOL_MESSAGE_TYPE::KerbPurgeBindingCacheMessage };
        void* response{ nullptr };
        return CallPackage(request, &response);
    }

    bool Api::PurgeKdcProxyCache(PLUID luid) const {
        KERB_PURGE_KDC_PROXY_CACHE_REQUEST request = { KERB_PROTOCOL_MESSAGE_TYPE::KerbPurgeKdcProxyCacheMessage };
        request.Flags = 0;
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        PKERB_PURGE_KDC_PROXY_CACHE_RESPONSE response{ nullptr };
        auto result{ CallPackage(request, &response) };
        if (result) {
            std::wcout << "CountOfPurged: " << response->CountOfPurged << std::endl;
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::PurgeTicketCache(PLUID luid, const std::wstring& serverName, const std::wstring& serverRealm) const {
        auto requestSize{ sizeof(KERB_PURGE_TKT_CACHE_REQUEST) + ((serverName.length() + serverRealm.length() + 2) * sizeof(wchar_t)) };
        std::string requestBytes(requestSize, '\0');
        auto request{ reinterpret_cast<PKERB_PURGE_TKT_CACHE_REQUEST>(requestBytes.data()) };
        request->MessageType = KERB_PROTOCOL_MESSAGE_TYPE::KerbPurgeTicketCacheMessage;
        request->LogonId.LowPart = luid->LowPart;
        request->LogonId.HighPart = luid->HighPart;
        if (!serverName.empty()) {
            auto ptrServerName{ reinterpret_cast<std::byte*>(request + 1) };
            std::memcpy(ptrServerName, serverName.data(), serverName.size() * sizeof(wchar_t));
            request->ServerName = WCharToUString(reinterpret_cast<wchar_t*>(ptrServerName));
        }
        if (!serverRealm.empty()) {
            auto ptrRealmName{ reinterpret_cast<std::byte*>(request + 1) + ((serverName.length() + 1) * sizeof(wchar_t)) };
            std::memcpy(ptrRealmName, serverRealm.data(), serverRealm.size() * sizeof(wchar_t));
            request->RealmName = WCharToUString(reinterpret_cast<wchar_t*>(ptrRealmName));
        }
        void* response{ nullptr };
        return CallPackage(requestBytes, reinterpret_cast<void**>(&response));
    }

    bool Api::PurgeTicketCacheEx(PLUID luid, ULONG flags, const std::wstring& clientName, const std::wstring& clientRealm, const std::wstring& serverName, const std::wstring& serverRealm) const {
        auto requestSize{ sizeof(KERB_PURGE_TKT_CACHE_EX_REQUEST) + ((clientName.length() + clientRealm.length() + serverName.length() + serverRealm.length() + 4) * sizeof(wchar_t)) };
        std::string requestBytes(requestSize, '\0');
        auto request{ reinterpret_cast<PKERB_PURGE_TKT_CACHE_EX_REQUEST>(requestBytes.data()) };
        request->MessageType = KERB_PROTOCOL_MESSAGE_TYPE::KerbPurgeTicketCacheExMessage;
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

    bool Api::QueryBindingCache() const {
        KERB_QUERY_BINDING_CACHE_REQUEST request{ KERB_PROTOCOL_MESSAGE_TYPE::KerbQueryBindingCacheMessage };
        PKERB_QUERY_BINDING_CACHE_RESPONSE response{ nullptr };
        auto result{ CallPackage(request, &response) };
        std::wcout << std::hex;
        if (result) {
            for (size_t index{ 0 }; index < response->CountOfEntries; index++) {
                auto& entry{ response->Entries[index] };
                std::wcout << index << ": " << std::endl;
                std::wcout << "    DiscoveryTime: 0x" << entry.DiscoveryTime << std::endl;
                std::wcout << "    RealmName    : " << ToWString(&entry.RealmName) << std::endl;
                std::wcout << "    KdcAddress   : " << ToWString(&entry.KdcAddress) << std::endl;
                std::wcout << "    AddressType  : 0x" << entry.AddressType << std::endl;
                std::wcout << "    Flags        : 0x" << entry.Flags << std::endl;
                std::wcout << "    DcFlags      : 0x" << entry.DcFlags << std::endl;
                std::wcout << "    CacheFlags   : 0x" << entry.CacheFlags << std::endl;
                std::wcout << "    KdcName      : " << ToWString(&entry.KdcName) << std::endl;
            }
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::QueryDomainExtendedPolicies(const std::wstring& domainName) const {
        auto requestSize{ sizeof(KERB_QUERY_DOMAIN_EXTENDED_POLICIES_REQUEST) + ((domainName.length() + 1) * sizeof(wchar_t)) };
        std::string requestBytes(requestSize, '\0');
        auto request{ reinterpret_cast<PKERB_QUERY_DOMAIN_EXTENDED_POLICIES_REQUEST>(requestBytes.data()) };
        request->MessageType = KERB_PROTOCOL_MESSAGE_TYPE::KerbQueryDomainExtendedPoliciesMessage;
        request->Flags = 0;
        auto ptrUstring{ reinterpret_cast<std::byte*>(request + 1) };
        std::memcpy(ptrUstring, domainName.data(), domainName.size() * sizeof(wchar_t));
        request->DomainName = WCharToUString(reinterpret_cast<wchar_t*>(ptrUstring));
        PKERB_QUERY_DOMAIN_EXTENDED_POLICIES_RESPONSE response{ nullptr };
        auto result{ CallPackage(requestBytes, reinterpret_cast<void**>(&response)) };
        std::wcout << std::hex;
        if (result) {
            std::wcout << "Flags           : " << response->Flags << std::endl;
            if (response->Flags & KERB_QUERY_DOMAIN_EXTENDED_POLICIES_RESPONSE_FLAG_DAC_DISABLED) {
                std::wcout << "        DAC_DISABLED" << std::endl;
            }
            std::cout << "ExtendedPolicies: " << response->ExtendedPolicies << std::endl;
            std::wcout << "DsFlags         : " << response->DsFlags << std::endl;
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::QueryKdcProxyCache(PLUID luid) const {
        KERB_QUERY_KDC_PROXY_CACHE_REQUEST request = { KERB_PROTOCOL_MESSAGE_TYPE::KerbQueryKdcProxyCacheMessage };
        request.Flags = 0;
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        PKERB_QUERY_KDC_PROXY_CACHE_RESPONSE response{ nullptr };
        auto result{ CallPackage(request, &response) };
        std::wcout << std::hex;
        if (result) {
            for (size_t index{ 0 }; index < response->CountOfEntries; index++) {
                auto& entry{ response->Entries[index] };
                std::wcout << index << ": " << std::endl;
                std::wcout << "    SinceLastUsed  : " << entry.SinceLastUsed << std::endl;
                std::wcout << "    DomainName     : " << ToWString(&entry.DomainName) << std::endl;
                std::wcout << "    ApiServerName: " << ToWString(&entry.ProxyServerName) << std::endl;
                std::wcout << "    ApiServerVdir: " << ToWString(&entry.ProxyServerVdir) << std::endl;
                std::wcout << "    ApiServerPort: " << entry.ProxyServerPort << std::endl;
                std::cout << "    LogonId        : " << std::setfill('0') << std::setw(8) << entry.LogonId.HighPart << "-" << std::setw(8) << entry.LogonId.LowPart << std::endl;
                std::wcout << "    CredUserName   : " << ToWString(&entry.CredUserName) << std::endl;
                std::wcout << "    CredDomainName : " << ToWString(&entry.CredDomainName) << std::endl;
                std::wcout << "    GlobalCache    : " << entry.GlobalCache << std::endl;
            }
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::QueryS4U2ProxyCache(PLUID luid) const {
        KERB_QUERY_S4U2PROXY_CACHE_REQUEST request = { KERB_PROTOCOL_MESSAGE_TYPE::KerbQueryS4U2ProxyCacheMessage };
        request.Flags = 0;
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        PKERB_QUERY_S4U2PROXY_CACHE_RESPONSE response{ nullptr };
        auto result{ CallPackage(request, &response) };
        std::wcout << std::hex;
        if (result) {
            for (size_t index{ 0 }; index < response->CountOfCreds; index++) {
                auto& cred{ response->Creds[index] };
                std::wcout << index << ": " << std::endl;
                std::wcout << "    UserName  : " << ToWString(&cred.UserName) << std::endl;
                std::wcout << "    DomainName: " << ToWString(&cred.DomainName) << std::endl;
                std::wcout << "    Flags     : " << cred.Flags << std::endl;
                std::wcout << "    LastStatus: " << cred.LastStatus << std::endl;
                std::wcout << "    Expiry    : " << cred.Expiry.QuadPart << std::endl;
                for (size_t index{ 0 }; index < cred.CountOfEntries; index++) {
                    std::wcout << "    Entry " << index << ": " << std::endl;
                    auto& entry{ cred.Entries[index] };
                    std::wcout << "        ServerName: " << ToWString(&entry.ServerName) << std::endl;
                    std::wcout << "        Flags     : " << entry.Flags << std::endl;
                    std::wcout << "        LastStatus: " << entry.LastStatus << std::endl;
                    std::wcout << "        Expiry    : " << entry.Expiry.QuadPart << std::endl;
                }
            }
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::QueryTicketCache(PLUID luid) const {
        KERB_QUERY_TKT_CACHE_REQUEST request = { KERB_PROTOCOL_MESSAGE_TYPE::KerbQueryTicketCacheMessage };
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        PKERB_QUERY_TKT_CACHE_RESPONSE response{ nullptr };
        auto result{ CallPackage(request, &response) };
        std::wcout << std::hex;
        if (result) {
            for (size_t index{ 0 }; index < response->CountOfTickets; index++) {
                auto& ticket{ response->Tickets[index] };
                std::wcout << index << ": " << std::endl;
                std::wcout << "    ServerName    : " << ToWString(&ticket.ServerName) << std::endl;
                std::wcout << "    RealmName     : " << ToWString(&ticket.RealmName) << std::endl;
                std::wcout << "    StartTime     : " << ticket.StartTime.QuadPart << std::endl;
                std::wcout << "    EndTime       : " << ticket.EndTime.QuadPart << std::endl;
                std::wcout << "    RenewTime     : " << ticket.RenewTime.QuadPart << std::endl;
                std::cout << "    EncryptionType: " << ticket.EncryptionType << std::endl;
                std::wcout << "    TicketFlags   : 0x" << std::hex << std::setw(4) << std::setfill(L'0') << ticket.TicketFlags << std::endl;
            }
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::QueryTicketCacheEx(PLUID luid) const {
        KERB_QUERY_TKT_CACHE_REQUEST request = { KERB_PROTOCOL_MESSAGE_TYPE::KerbQueryTicketCacheExMessage };
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        PKERB_QUERY_TKT_CACHE_EX_RESPONSE response{ nullptr };
        auto result{ CallPackage(request, &response) };
        std::wcout << std::hex;
        if (result) {
            for (size_t index{ 0 }; index < response->CountOfTickets; index++) {
                auto& ticket{ response->Tickets[index] };
                std::wcout << index << ": " << std::endl;
                std::wcout << "    ClientName    : " << ToWString(&ticket.ClientName) << std::endl;
                std::wcout << "    ClientRealm   : " << ToWString(&ticket.ClientRealm) << std::endl;
                std::wcout << "    ServerName    : " << ToWString(&ticket.ServerName) << std::endl;
                std::wcout << "    ServerRealm   : " << ToWString(&ticket.ServerRealm) << std::endl;
                std::wcout << "    StartTime     : " << ticket.StartTime.QuadPart << std::endl;
                std::wcout << "    EndTime       : " << ticket.EndTime.QuadPart << std::endl;
                std::wcout << "    RenewTime     : " << ticket.RenewTime.QuadPart << std::endl;
                std::cout << "    EncryptionType: " << ticket.EncryptionType << std::endl;
                std::wcout << "    TicketFlags   : 0x" << std::hex << std::setw(4) << std::setfill(L'0') << ticket.TicketFlags << std::endl;
            }
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::QueryTicketCacheEx2(PLUID luid) const {
        KERB_QUERY_TKT_CACHE_REQUEST request = { KERB_PROTOCOL_MESSAGE_TYPE::KerbQueryTicketCacheEx2Message };
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        PKERB_QUERY_TKT_CACHE_EX2_RESPONSE response{ nullptr };
        auto result{ CallPackage(request, &response) };
        std::wcout << std::hex;
        if (result) {
            for (size_t index{ 0 }; index < response->CountOfTickets; index++) {
                auto& ticket{ response->Tickets[index] };
                std::wcout << index << ": " << std::endl;
                std::wcout << "    ClientName    : " << ToWString(&ticket.ClientName) << std::endl;
                std::wcout << "    ClientRealm   : " << ToWString(&ticket.ClientRealm) << std::endl;
                std::wcout << "    ServerName    : " << ToWString(&ticket.ServerName) << std::endl;
                std::wcout << "    ServerRealm   : " << ToWString(&ticket.ServerRealm) << std::endl;
                std::wcout << "    StartTime     : " << ticket.StartTime.QuadPart << std::endl;
                std::wcout << "    EndTime       : " << ticket.EndTime.QuadPart << std::endl;
                std::wcout << "    RenewTime     : " << ticket.RenewTime.QuadPart << std::endl;
                std::cout << "    EncryptionType: " << ticket.EncryptionType << std::endl;
                std::wcout << "    TicketFlags   : 0x" << std::hex << std::setw(4) << std::setfill(L'0') << ticket.TicketFlags << std::endl;
                std::cout << "    SessionKeyType: " << ticket.SessionKeyType << std::endl;
                std::wcout << "    BranchId      : " << ticket.BranchId << std::endl;
            }
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::QueryTicketCacheEx3(PLUID luid) const {
        KERB_QUERY_TKT_CACHE_REQUEST request = { KERB_PROTOCOL_MESSAGE_TYPE::KerbQueryTicketCacheEx3Message };
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        PKERB_QUERY_TKT_CACHE_EX3_RESPONSE response{ nullptr };
        auto result{ CallPackage(request, &response) };
        std::wcout << std::hex;
        if (result) {
            for (size_t index{ 0 }; index < response->CountOfTickets; index++) {
                auto& ticket{ response->Tickets[index] };
                std::wcout << index << ": " << std::endl;
                std::wcout << "    ClientName    : " << ToWString(&ticket.ClientName) << std::endl;
                std::wcout << "    ClientRealm   : " << ToWString(&ticket.ClientRealm) << std::endl;
                std::wcout << "    ServerName    : " << ToWString(&ticket.ServerName) << std::endl;
                std::wcout << "    ServerRealm   : " << ToWString(&ticket.ServerRealm) << std::endl;
                std::wcout << "    StartTime     : " << ticket.StartTime.QuadPart << std::endl;
                std::wcout << "    EndTime       : " << ticket.EndTime.QuadPart << std::endl;
                std::wcout << "    RenewTime     : " << ticket.RenewTime.QuadPart << std::endl;
                std::cout << "    EncryptionType: " << ticket.EncryptionType << std::endl;
                std::wcout << "    TicketFlags   : 0x" << std::hex << std::setw(4) << std::setfill(L'0') << ticket.TicketFlags << std::endl;
                std::cout << "    SessionKeyType: " << ticket.SessionKeyType << std::endl;
                std::wcout << "    BranchId      : " << ticket.BranchId << std::endl;
                std::wcout << "    CacheFlags    : " << ticket.CacheFlags << std::endl;
                std::wcout << "    KdcCalled     : " << ToWString(&ticket.KdcCalled) << std::endl;
            }
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::RetrieveEncodedTicket(PLUID luid, const std::wstring& targetName, DWORD flags, DWORD options, DWORD type) const {
        return RetrieveTicket(luid, targetName, flags, options, type, true);
    }

    bool Api::RetrieveKeyTab(const std::wstring& domainName, const std::wstring& userName, const std::wstring& password) const {
        auto requestSize{ sizeof(KERB_RETRIEVE_KEY_TAB_REQUEST) + ((domainName.length() + userName.length() + password.length() + 3) * sizeof(wchar_t)) };
        std::string requestBytes(requestSize, '\0');
        auto request{ reinterpret_cast<PKERB_RETRIEVE_KEY_TAB_REQUEST>(requestBytes.data()) };
        request->MessageType = KERB_PROTOCOL_MESSAGE_TYPE::KerbRetrieveKeyTabMessage;
        request->Flags = 0; // The flags field is ignored

        auto ptrUstring{ reinterpret_cast<std::byte*>(request + 1) };
        std::memcpy(ptrUstring, domainName.data(), domainName.size() * sizeof(wchar_t));
        request->DomainName = WCharToUString(reinterpret_cast<wchar_t*>(ptrUstring));

        ptrUstring = ptrUstring + ((domainName.length() + 1) * sizeof(wchar_t));
        std::memcpy(ptrUstring, userName.data(), userName.size() * sizeof(wchar_t));
        request->UserName = WCharToUString(reinterpret_cast<wchar_t*>(ptrUstring));

        ptrUstring = ptrUstring + ((userName.length() + 1) * sizeof(wchar_t));
        std::memcpy(ptrUstring, password.data(), password.size() * sizeof(wchar_t));
        request->Password = WCharToUString(reinterpret_cast<wchar_t*>(ptrUstring));

        PKERB_RETRIEVE_KEY_TAB_RESPONSE response{ nullptr };
        auto result{ CallPackage(requestBytes, reinterpret_cast<void**>(&response)) };
        if (result) {
            OutputHex(lsa->out, "KeyTab", std::string{ response->KeyTab, response->KeyTab + response->KeyTabLength });
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::RetrieveTicket(PLUID luid, const std::wstring& targetName, DWORD flags, DWORD options, DWORD type, bool encoded) const {
        std::string requestBytes(sizeof(KERB_RETRIEVE_TKT_REQUEST) + (targetName.size() * sizeof(wchar_t) + 2), '\0');
        auto request{ reinterpret_cast<PKERB_RETRIEVE_TKT_REQUEST>(requestBytes.data()) };
        request->MessageType = static_cast<KERB_PROTOCOL_MESSAGE_TYPE>((encoded) ? KERB_PROTOCOL_MESSAGE_TYPE::KerbRetrieveEncodedTicketMessage : PROTOCOL_MESSAGE_TYPE::KerbRetrieveTicketMessage);
        request->LogonId.LowPart = luid->LowPart;
        request->LogonId.HighPart = luid->HighPart;
        request->TargetName.Length = targetName.size() * sizeof(wchar_t);
        request->TargetName.MaximumLength = request->TargetName.Length + sizeof(wchar_t);
        auto targetNameData{ reinterpret_cast<wchar_t*>(request + 1) };
        std::memcpy(targetNameData, targetName.data(), request->TargetName.MaximumLength); //
        request->TargetName.Buffer = targetNameData;
        request->TicketFlags = static_cast<ULONG>(flags);
        request->CacheOptions = static_cast<ULONG>(options);
        request->EncryptionType = static_cast<ULONG>(type);
        request->CredentialsHandle = { 0 };
        KERB_RETRIEVE_TKT_RESPONSE* response{ nullptr };
        // The CallPackage(const std::string&, void**) function must be used
        // Otherwise a new string will be implicitly constructed and the buffer's internal addresses will not be correct
        auto result{ CallPackage(requestBytes, reinterpret_cast<void**>(&response)) };
        if (result) {
            auto& ticket{ response->Ticket };
            std::wcout << "ServiceName         : ";
            for (size_t index{ 0 }; index < ticket.ServiceName->NameCount; index++) {
                if (index) {
                    std::wcout << "/";
                }
                auto& name{ ticket.ServiceName->Names[index] };
                std::wcout << ToWString(&name);
            }
            std::wcout << " (Type " << ticket.ServiceName->NameType << ") " << std::endl;

            std::wcout << "TargetName          : ";
            for (size_t index{ 0 }; index < ticket.TargetName->NameCount; index++) {
                if (index) {
                    std::wcout << "/";
                }
                auto& name{ ticket.TargetName->Names[index] };
                std::wcout << ToWString(&name);
            }
            std::wcout << " (Type " << ticket.TargetName->NameType << ") " << std::endl;

            std::wcout << "ClientName          : ";
            for (size_t index{ 0 }; index < ticket.ClientName->NameCount; index++) {
                if (index) {
                    std::wcout << "/";
                }
                auto& name{ ticket.ClientName->Names[index] };
                std::wcout << ToWString(&name);
            }
            std::wcout << " (Type " << ticket.ClientName->NameType << ") " << std::endl;
            std::wcout << "DomainName          : " << ToWString(&ticket.DomainName) << std::endl;
            std::wcout << "TargetDomainName    : " << ToWString(&ticket.TargetDomainName) << std::endl;
            std::wcout << "AltTargetDomainName : " << ToWString(&ticket.AltTargetDomainName) << std::endl;
            std::cout << "SessionKey Type     : " << ticket.SessionKey.KeyType << std::endl;
            OutputHex(lsa->out, "SessionKey Value", std::string{ ticket.SessionKey.Value, ticket.SessionKey.Value + ticket.SessionKey.Length });
            std::wcout << "TicketFlags         : " << ticket.TicketFlags << std::endl;
            std::wcout << "Flags               : " << ticket.Flags << std::endl;
            std::wcout << "KeyExpirationTime   : " << ticket.KeyExpirationTime.QuadPart << std::endl;
            std::wcout << "StartTime           : " << ticket.StartTime.QuadPart << std::endl;
            std::wcout << "EndTime             : " << ticket.EndTime.QuadPart << std::endl;
            std::wcout << "RenewUntil          : " << ticket.RenewUntil.QuadPart << std::endl;
            std::wcout << "TimeSkew            : " << ticket.TimeSkew.QuadPart << std::endl;
            OutputHex(lsa->out, "EncodedTicket", std::string{ ticket.EncodedTicket, ticket.EncodedTicket + ticket.EncodedTicketSize });
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::TransferCreds(PLUID sourceLuid, PLUID destinationLuid, ULONG flags) const {
        SECPKG_CALL_PACKAGE_TRANSFER_CRED_REQUEST request = { KERB_PROTOCOL_MESSAGE_TYPE::KerbTransferCredentialsMessage };
        request.OriginLogonId.LowPart = sourceLuid->LowPart;
        request.OriginLogonId.HighPart = sourceLuid->HighPart;
        request.DestinationLogonId.LowPart = destinationLuid->LowPart;
        request.DestinationLogonId.HighPart = destinationLuid->HighPart;
        request.Flags = flags;
        void* response;
        return CallPackage(request, &response);
    }

    bool Api::UnpinAllKdcs() const {
        SECPKG_CALL_PACKAGE_UNPIN_ALL_DCS_REQUEST request = { KERB_PROTOCOL_MESSAGE_TYPE::KerbUnpinAllKdcsMessage };
        request.Flags = 0;
        void* response{ nullptr };
        return CallPackage(request, &response);
    }

    bool Api::CallPackage(const std::string& submitBuffer, void** returnBuffer) const {
        if (lsa->Connected()) {
            return lsa->CallPackage(MICROSOFT_KERBEROS_NAME_A, submitBuffer, returnBuffer);
        }
        return false;
    }

    template<typename _Request, typename _Response>
    bool Api::CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const {
        std::string stringSubmitBuffer(reinterpret_cast<const char*>(&submitBuffer), sizeof(decltype(submitBuffer)));
        return CallPackage(stringSubmitBuffer, reinterpret_cast<void**>(returnBuffer));
    }

    template<typename _Request, typename _Response>
    bool Api::CallPackage(_Request* submitBuffer, size_t submitBufferLength, _Response** returnBuffer) const {
        std::string stringSubmitBuffer(reinterpret_cast<const char*>(submitBuffer), submitBufferLength);
        return CallPackage(stringSubmitBuffer, reinterpret_cast<void**>(returnBuffer));
    }
}