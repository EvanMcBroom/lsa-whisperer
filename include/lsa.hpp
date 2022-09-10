#pragma once
#include <string>

class UnicodeString : public UNICODE_STRING {
public:
    UnicodeString(std::wstring data);
    ~UnicodeString();
};

bool CallPackage(const std::string& package, const std::string& submitBuffer, void** returnBuffer);
PSID MakeDomainRelativeSid(PSID DomainId, ULONG RelativeId);
void OutputHex(const std::string& data);
void OutputHex(const std::string& prompt, const std::string& data);