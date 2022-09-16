#pragma once
#define _NTDEF_ // Required to include both Ntsecapi and Winternl
#include <Winternl.h>
#include <string>

class UnicodeString : public UNICODE_STRING {
public:
    UnicodeString(std::wstring data);
    ~UnicodeString();
};

class Lsa {
public:
    Lsa();
    ~Lsa();
    bool CallPackage(const std::string& package, const std::string& submitBuffer, void** returnBuffer);
    auto Connected() { return connected; };

private:
    bool connected{ false };
    HANDLE lsaHandle;
};

class SspiProxy {
public:
    SspiProxy(const std::shared_ptr<Lsa>& lsa);

protected:
    std::shared_ptr<Lsa> lsa;
};

PSID MakeDomainRelativeSid(PSID DomainId, ULONG RelativeId);
void OutputHex(const std::string& data);
void OutputHex(const std::string& prompt, const std::string& data);