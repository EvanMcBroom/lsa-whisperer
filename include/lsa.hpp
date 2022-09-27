#pragma once
#define _NTDEF_ // Required to include both Ntsecapi and Winternl
#include <Winternl.h>
#include <iostream>
#include <string>

class UnicodeString : public UNICODE_STRING {
public:
    UnicodeString(std::wstring data);
    ~UnicodeString();
};

// https://stackoverflow.com/a/46455079
class NullStream : public std::ostream {
public:
    NullStream() : std::ostream(&nullBuffer) {}

private:
    class NullBuffer : public std::streambuf {
    public:
        int overflow(int c) { return c; }
    } nullBuffer;
};

class Lsa {
public:
    std::ostream& out;

    Lsa(std::ostream& out = NullStream());
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
void OutputHex(std::ostream& out, const std::string& data);
void OutputHex(std::ostream& out, const std::string& prompt, const std::string& data);