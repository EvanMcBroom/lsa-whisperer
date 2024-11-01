#define _NTDEF_ // Required to include both Ntsecapi and Winternl
#include <Winternl.h>
#include <iomanip>
#include <iostream>
#include <all.hpp>
#include <live.hpp>
#include <lsa.hpp>
#include <magic_enum/magic_enum.hpp>
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

namespace AllPackages {
    Proxy::Proxy(const std::shared_ptr<Lsa>& lsa)
        : lsa(lsa) {
    }

    
    bool Proxy::PinDc(const std::wstring& domainName, const std::wstring& dcName, ULONG dcFlags) const {
        auto requestSize{ sizeof(SECPKG_CALL_PACKAGE_PIN_DC_REQUEST) + ((domainName.length() + dcName.length() + 2) * sizeof(wchar_t)) };
        std::string requestBytes(requestSize, '\0');
        auto request{ reinterpret_cast<PSECPKG_CALL_PACKAGE_PIN_DC_REQUEST>(requestBytes.data()) };
        request->MessageType = SecPkgCallPackagePinDcMessage;
        request->Flags = 0; // Should be ignored by APs
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

    bool Proxy::UnpinAllDcs() const {
        auto requestSize{ sizeof(SECPKG_CALL_PACKAGE_UNPIN_ALL_DCS_REQUEST) };
        std::string requestBytes(requestSize, '\0');
        auto request{ reinterpret_cast<PSECPKG_CALL_PACKAGE_UNPIN_ALL_DCS_REQUEST>(requestBytes.data()) };
        request->MessageType = SecPkgCallPackageUnpinAllDcsMessage;
        request->Flags = 0; // Should be ignored by APs
        void* response{ nullptr };
        return CallPackage(requestBytes, reinterpret_cast<void**>(&response));
    }

    bool Proxy::TransferCred(PLUID sourceLuid, PLUID destinationLuid, ULONG flags) const {
        auto requestSize{ sizeof(SECPKG_CALL_PACKAGE_TRANSFER_CRED_REQUEST) };
        std::string requestBytes(requestSize, '\0');
        auto request{ reinterpret_cast<PSECPKG_CALL_PACKAGE_TRANSFER_CRED_REQUEST>(requestBytes.data()) };
        request->MessageType = SecPkgCallPackageTransferCredMessage;
        request->OriginLogonId.HighPart = sourceLuid->HighPart;
        request->OriginLogonId.LowPart = sourceLuid->LowPart;
        request->DestinationLogonId.HighPart = sourceLuid->HighPart;
        request->DestinationLogonId.LowPart = sourceLuid->LowPart;
        request->Flags = flags;
        void* response{ nullptr };
        return CallPackage(requestBytes, reinterpret_cast<void**>(&response));
    }

    bool Proxy::CallPackage(const std::string& submitBuffer, void** returnBuffer) const {
        if (lsa->Connected()) {
            return lsa->CallAllPackages(submitBuffer, returnBuffer);
        }
        return false;
    }
}