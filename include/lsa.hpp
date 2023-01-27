#pragma once
#define _NTDEF_ // Required to include both Ntsecapi and Winternl
#include <Winternl.h>
#include <NTSecAPI.h>
#include <iostream>
#include <rpc.hpp>
#include <spm.hpp>
#include <string>
#include <vector>
#include <ms-sspir_c.h>

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
    Sspi(const std::wstring& server);
    // Will call LsaRegisterLogonProcess/SspirConnectRpc
    Sspi(const std::wstring& server, const std::string& logonProcessName);
    // Will call LsaDeregisterLogonProcess/SspirDisconnectRpc
    ~Sspi();

    bool Connected();

    // The authentication package APIs
    // Any returned data should be deallocated with std::free
    NTSTATUS LsaCallAuthenticationPackage(ULONG AuthenticationPackage, PVOID ProtocolSubmitBuffer, ULONG SubmitBufferLength, PVOID* ProtocolReturnBuffer, PULONG ReturnBufferLength, PNTSTATUS ProtocolStatus);
    NTSTATUS LsaLookupAuthenticationPackage(PSTRING PackageName, PULONG AuthenticationPackage);

private:
    const RPC_WSTR alpcPort{ reinterpret_cast<RPC_WSTR>(L"lsasspirpc") };
    bool connected{ false };
    HANDLE lsaHandle{ nullptr };
    //LSA_OPERATIONAL_MODE_LPC operationalMode{ 0 };
    long operationalMode{ 0 };
    long packageCount{ 0 };
    std::unique_ptr<Rpc::Client> rpcClient{ nullptr };

    // Call a security package manager (SPM) API
    NTSTATUS CallSpmApi(PORT_MESSAGE* message, size_t* outputSize, void** output);
    void RpcConnect();
};

class Lsa {
public:
    std::ostream& out;

    Lsa(std::ostream& out = NullStream(), bool useRpc = true);
    ~Lsa();
    bool CallPackage(const std::string& package, const std::string& submitBuffer, void** returnBuffer) const;
    // Uses the GenericPassthrough message implemented by msv1_0
    // Data will be used as an input and output argument. It's original values will be cleared if the call is successful
    bool CallPackagePassthrough(const std::wstring& domainName, const std::wstring& packageName, std::vector<byte>& data) const;
    auto Connected() { return connected; };

private:
    bool connected{ false };
    HANDLE lsaHandle;
    bool useRpc;
    std::unique_ptr<Sspi> sspi;
};

void OutputHex(std::ostream& out, const std::string& data);
void OutputHex(std::ostream& out, const std::string& prompt, const std::string& data);