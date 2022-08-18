#pragma once
#include <memory>
#include <netlogon.hpp>
#include <string>
#include <vector>

// The GetSupplementalMitCreds function is only provided for convenience
// Other supplemental cred formats are left to the user to build

std::unique_ptr<Netlogon::INTERACTIVE_INFO> GetLogonInfo(const std::wstring& domainName, const std::wstring& userName, std::shared_ptr<std::wstring>& computerName, const std::vector<byte>& hash, ULONG logonType = RPC_C_AUTHN_GSS_KERBEROS);
std::vector<byte> GetSupplementalMitCreds(const std::wstring& domainName, const std::wstring& upn);
// The validationInfo argument is specified as VALIDATION_SAM_INFO3 because may store resource group information
std::unique_ptr<Netlogon::VALIDATION_SAM_INFO4> GetValidationInfo(Netlogon::PVALIDATION_SAM_INFO3 validationInfo, std::wstring* dnsDomainName);