#pragma once
#include <Windows.h>
#include <MsChapp.h>
#include <Ntsecapi.h>
#include <crypt.hpp>

// Sam definitions included with netlogon.hpp for convenience
namespace Sam {
    typedef struct _GROUP_MEMBERSHIP {
        ULONG RelativeId;
        ULONG Attributes;
    } GROUP_MEMBERSHIP, * PGROUP_MEMBERSHIP;
}

namespace Netlogon {
    typedef struct _LOGON_IDENTITY_INFO {
        UNICODE_STRING LogonDomainName;
        ULONG ParameterControl;
        LARGE_INTEGER  LogonId;
        UNICODE_STRING UserName;
        UNICODE_STRING Workstation;
    } LOGON_IDENTITY_INFO, * PLOGON_IDENTITY_INFO;

    typedef struct _INTERACTIVE_INFO {
        LOGON_IDENTITY_INFO Identity;
        LM_OWF_PASSWORD LmOwfPassword;
        NT_OWF_PASSWORD NtOwfPassword;
    } INTERACTIVE_INFO, * PINTERACTIVE_INFO;

    typedef struct _SID_AND_ATTRIBUTES {
        PSID Sid;
        ULONG Attributes;
    } SID_AND_ATTRIBUTES, * PSID_AND_ATTRIBUTES;

    typedef struct _VALIDATION_SAM_INFO {
        // Information retrieved from SAM.
        LARGE_INTEGER LogonTime{ 0 };
        LARGE_INTEGER LogoffTime;
        LARGE_INTEGER KickOffTime;
        LARGE_INTEGER PasswordLastSet{ 0 };
        LARGE_INTEGER PasswordCanChange{ 0 };
        LARGE_INTEGER PasswordMustChange{ 0 };
        UNICODE_STRING EffectiveName{ 0 };
        UNICODE_STRING FullName{ 0 };
        UNICODE_STRING LogonScript{ 0 };
        UNICODE_STRING ProfilePath{ 0 };
        UNICODE_STRING HomeDirectory{ 0 };
        UNICODE_STRING HomeDirectoryDrive{ 0 };
        USHORT LogonCount{ 0 };
        USHORT BadPasswordCount{ 0 };
        ULONG UserId;
        ULONG PrimaryGroupId;
        ULONG GroupCount;
        Sam::PGROUP_MEMBERSHIP GroupIds;
        // Information supplied by the MSV AP/Netlogon service.
        ULONG UserFlags;
        USER_SESSION_KEY UserSessionKey;
        UNICODE_STRING LogonServer;
        UNICODE_STRING LogonDomainName;
        PSID LogonDomainId;
        // For info 4:
        // - The First two longwords (8 bytes) of ExpansionRoom are reserved for the LanManSession Key.
        // - The third longword (4 bytes) of ExpansionRoom is the user account control flag from the account.
        // - The fourth longword (4 bytes) of ExpansionRoom is for the status returned for subauth users, not from subauth packages (NT5 onwards)
        ULONG ExpansionRoom[10]; // Reserved for new fields
    } VALIDATION_SAM_INFO, * PVALIDATION_SAM_INFO;

    typedef struct _VALIDATION_SAM_INFO2 : public VALIDATION_SAM_INFO {
        // The new fields in this structure are a count and a pointer to an array of SIDs and attributes.
        ULONG SidCount;
        PSID_AND_ATTRIBUTES ExtraSids;
    } VALIDATION_SAM_INFO2, * PVALIDATION_SAM_INFO2;

    typedef struct _VALIDATION_SAM_INFO3 : public VALIDATION_SAM_INFO2 {
        // Resource groups. These are present if LOGON_RESOURCE_GROUPS bit is set in the user flags
        PSID ResourceGroupDomainSid;
        ULONG ResourceGroupCount;
        Sam::PGROUP_MEMBERSHIP ResourceGroupIds;
    } VALIDATION_SAM_INFO3, * PVALIDATION_SAM_INFO3;

    // Info 4 is derived from info 2, not info 3
    typedef struct _VALIDATION_SAM_INFO4 : public VALIDATION_SAM_INFO2 {
        // New fields added for version 4 of the structure
        UNICODE_STRING DnsLogonDomainName; // Dns version of LogonDomainName
        UNICODE_STRING Upn; // UPN of the user account
        // Reserved for new fields
        UNICODE_STRING ExpansionString1; 
        UNICODE_STRING ExpansionString2;
        UNICODE_STRING ExpansionString3;
        UNICODE_STRING ExpansionString4;
        UNICODE_STRING ExpansionString5;
        UNICODE_STRING ExpansionString6;
        UNICODE_STRING ExpansionString7;
        UNICODE_STRING ExpansionString8;
        UNICODE_STRING ExpansionString9;
        UNICODE_STRING ExpansionString10;
    } VALIDATION_SAM_INFO4, * PVALIDATION_SAM_INFO4;
}