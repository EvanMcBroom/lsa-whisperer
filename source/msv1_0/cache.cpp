#define _NTDEF_ // Required to include both Ntsecapi and Winternl
#include <Winternl.h>
#include <msv1_0/cache.hpp>
#include <netlogon.hpp>

namespace {
    // The Rtl* functions were dynamically resolved to save time during development
    PSID MakeDomainRelativeSid(PSID DomainId, ULONG RelativeId) {
        PSID result{ nullptr };
        auto library{ LoadLibraryW(L"ntdll.dll") };
        if (library) {
            using PRtlCopySid = NTSTATUS(*)(ULONG DestinationSidLength, PSID DestinationSid, PSID SourceSid);
            auto RtlCopySid{ reinterpret_cast<PRtlCopySid>(GetProcAddress(library, "RtlCopySid")) };
            using PRtlLengthRequiredSid = ULONG(*)(ULONG SubAuthorityCount);
            auto RtlLengthRequiredSid{ reinterpret_cast<PRtlLengthRequiredSid>(GetProcAddress(library, "RtlLengthRequiredSid")) };
            using PRtlSubAuthorityCountSid = PUCHAR(*)(PSID pSid);
            auto RtlSubAuthorityCountSid{ reinterpret_cast<PRtlSubAuthorityCountSid>(GetProcAddress(library, "RtlSubAuthorityCountSid")) };
            using PRtlSubAuthoritySid = LPDWORD(*)(PSID pSid, DWORD nSubAuthority);
            auto RtlSubAuthoritySid{ reinterpret_cast<PRtlSubAuthoritySid>(GetProcAddress(library, "RtlSubAuthoritySid")) };
            if (RtlCopySid && RtlLengthRequiredSid && RtlSubAuthorityCountSid && RtlSubAuthoritySid) {
                auto subAuthorityCount{ *(RtlSubAuthorityCountSid(DomainId)) }; // Should not fail
                auto length{ RtlLengthRequiredSid(subAuthorityCount + 1) }; // Should not fail
                auto sid{ reinterpret_cast<PSID>(std::malloc(length)) }; // Assume this succeeds for brevity
                if (SUCCEEDED(RtlCopySid(length, sid, DomainId))) {
                    (*(RtlSubAuthorityCountSid(sid)))++;
                    *RtlSubAuthoritySid(sid, subAuthorityCount) = RelativeId;
                    result = sid;
                }
            }
            FreeLibrary(library);
        }
        return result;
    }

    constexpr size_t RoundUp(size_t count, size_t powerOfTwo) {
        return (count + powerOfTwo - 1) & (~powerOfTwo - 1);
    }
}

std::unique_ptr<Netlogon::INTERACTIVE_INFO> GetLogonInfo(const std::wstring& domainName, const std::wstring& userName, std::wstring& computerName, const std::vector<byte>& hash, ULONG logonType) {
    auto logonInfo{ std::make_unique<Netlogon::INTERACTIVE_INFO>() };
    std::memset(logonInfo.get(), 0, sizeof(Netlogon::INTERACTIVE_INFO));
    // Populate the Identity portion of logonInfo
    auto& identity{ logonInfo->Identity };
    RtlInitUnicodeString(&identity.LogonDomainName, domainName.data());
    identity.ParameterControl = logonType;
    RtlInitUnicodeString(&identity.UserName, userName.data());
    if (!computerName.size()) {
        // For setting Workstation, there is no need to call GetComputerNameW twice to get the length
        // The value is the NetBIOS name which is at most 16 characters followed by a null terminator
        computerName = std::wstring(16 + 1, '\0');
        auto size{ static_cast<DWORD>(computerName.size()) };
        GetComputerNameW(computerName.data(), &size); // Assume this works for brevity
    }
    RtlInitUnicodeString(&identity.Workstation, computerName.data());
    // Populate the remainder of logonInfo
    std::memcpy(&logonInfo->NtOwfPassword, hash.data(), hash.size());
    return logonInfo;
}

std::vector<byte> GetSupplementalMitCreds(const std::wstring& domainName, const std::wstring& upn) {
    std::vector<byte> supplementalCreds((2 * sizeof(UNICODE_STRING)) + RoundUp(upn.length() * sizeof(wchar_t), sizeof(LONG)) + RoundUp(domainName.length() * sizeof(wchar_t), sizeof(LONG)), 0);
    // Add a unicode string for the UPN and immediately follow it with the UPN data
    UNICODE_STRING unicodeString;
    unicodeString.Length = upn.length();
    unicodeString.MaximumLength = upn.length();
    auto dataPtr{ reinterpret_cast<byte*>(supplementalCreds.data()) + sizeof(UNICODE_STRING) };
    if (unicodeString.Length > 0) {
        std::memcpy(dataPtr, upn.data(), upn.length() * sizeof(wchar_t));
        unicodeString.Buffer = (PWSTR)(reinterpret_cast<byte*>(supplementalCreds.data()) - reinterpret_cast<byte*>(dataPtr));
    }
    else {
        unicodeString.Buffer = nullptr;
    }
    std::memcpy(supplementalCreds.data(), &unicodeString, sizeof(UNICODE_STRING));
    // Add a unicode string for the domain name and immediately follow it with the domain name data
    dataPtr += RoundUp(unicodeString.Length * sizeof(wchar_t), sizeof(LONG)) + sizeof(UNICODE_STRING);
    unicodeString.Length = domainName.length();
    unicodeString.MaximumLength = domainName.length();
    if (unicodeString.Length > 0) {
        std::memcpy(dataPtr, domainName.data(), domainName.length() * sizeof(wchar_t));
        unicodeString.Buffer = (PWSTR)(reinterpret_cast<byte*>(supplementalCreds.data()) - reinterpret_cast<byte*>(dataPtr));
    }
    else {
        unicodeString.Buffer = nullptr;
    }
    std::memcpy(dataPtr - sizeof(UNICODE_STRING), &unicodeString, sizeof(UNICODE_STRING));
    return supplementalCreds;
}

// Populate the validation info to pass to MSV1_0
// MSV1_0 supports both INFO2 and INFO4
// We use INFO4 because it may store a UPN if needed
std::unique_ptr<Netlogon::VALIDATION_SAM_INFO4> GetValidationInfo(Netlogon::PVALIDATION_SAM_INFO3 validationInfo, std::wstring* dnsDomainName) {
    auto validationInfoToUse{ std::make_unique<Netlogon::VALIDATION_SAM_INFO4>() };
    std::memset(validationInfoToUse.get(), 0, sizeof(Netlogon::VALIDATION_SAM_INFO4));
    std::memcpy(&validationInfoToUse, validationInfo, sizeof(Netlogon::VALIDATION_SAM_INFO2));
    // Add any resource groups that exist in the input validation structure
    // They will be stored in ExtraSids because INFO4 does not support them
    if (validationInfo->UserFlags & LOGON_RESOURCE_GROUPS) {
        if (validationInfo->ResourceGroupCount != 0) {
            auto newGroupCount{ validationInfo->SidCount + validationInfo->ResourceGroupCount };
            auto newGroups{ reinterpret_cast<Netlogon::PSID_AND_ATTRIBUTES>(std::malloc(sizeof(Netlogon::SID_AND_ATTRIBUTES) * newGroupCount)) }; // Assume this works for brevity
            std::memcpy(newGroups, validationInfo->ExtraSids, validationInfo->SidCount * sizeof(Netlogon::SID_AND_ATTRIBUTES));
            auto sidCount{ validationInfo->SidCount };
            for (auto index{ 0 }; index < validationInfo->ResourceGroupCount; index++) {
                newGroups[sidCount + index].Attributes = validationInfo->ResourceGroupIds[index].Attributes;
                newGroups[sidCount + index].Sid = MakeDomainRelativeSid(validationInfo->ResourceGroupDomainSid, validationInfo->ResourceGroupIds[index].RelativeId); // Assume this works for brevity
            }
            Netlogon::VALIDATION_SAM_INFO2 info2;
            info2.UserFlags |= LOGON_EXTRA_SIDS;
            info2.SidCount = newGroupCount;
            info2.ExtraSids = newGroups;
            std::memcpy(&validationInfoToUse, &info2, sizeof(Netlogon::VALIDATION_SAM_INFO2));
        }
    }
    if (dnsDomainName) {
        RtlInitUnicodeString(&validationInfoToUse->DnsLogonDomainName, dnsDomainName->data());
    }
    return validationInfoToUse;
}