#pragma once
#define _NTDEF_ // Required to include both Ntsecapi and Winternl
#include <Winternl.h>
#include <iostream>
#include <string>
#include <vector>

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

// Reimplements Windows functions that use the SSPI RPC interface
class Sspi {
public:
    // Will call LsaConnectUntrusted/SspirConnectRpc
    Sspi();
    // Will call LsaDeregisterLogonProcess/SspirDisconnectRpc
    ~Sspi();

    bool Connected();
    NTSTATUS LsaCallAuthenticationPackage(ULONG AuthenticationPackage, PVOID ProtocolSubmitBuffer, ULONG SubmitBufferLength, PVOID* ProtocolReturnBuffer, PULONG ReturnBufferLength, PNTSTATUS ProtocolStatus);

private:
    bool connected;
    HANDLE lsaHandle;
    long packageCount{ 0 };
};

class Lsa {
public:
    std::ostream& out;

    Lsa(std::ostream& out = NullStream());
    ~Lsa();
    bool CallPackage(const std::string& package, const std::string& submitBuffer, void** returnBuffer) const;
    // Uses the GenericPassthrough message implemented by msv1_0
    // Data will be used as an input and output argument. It's original values will be cleared if the call is successful
    bool CallPackagePassthrough(const std::wstring& domainName, const std::wstring& packageName, std::vector<byte>& data) const;
    auto Connected() { return connected; };

private:
    bool connected{ false };
    HANDLE lsaHandle;
};

void OutputHex(std::ostream& out, const std::string& data);
void OutputHex(std::ostream& out, const std::string& prompt, const std::string& data);