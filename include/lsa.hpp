#pragma once
#include <pch.hpp>

#include <iostream>
#include <ms-sspir_c.h>
#include <rpc.hpp>
#include <spm.hpp>
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
    NullStream()
        : std::ostream(&nullBuffer) {}

private:
    class NullBuffer : public std::streambuf {
    public:
        int overflow(int c) {
            return c;
        }
    } nullBuffer;
};

enum class TransferCredFlag {
    OptimisticLogon = 1, // SECPKG_CALL_PACKAGE_TRANSFER_CRED_REQUEST_FLAG_OPTIMISTIC_LOGON
    CleanupCredentials = 2, // SECPKG_CALL_PACKAGE_TRANSFER_CRED_REQUEST_FLAG_CLEANUP_CREDENTIALS
    ToSsoSession = 4, // SECPKG_CALL_PACKAGE_TRANSFER_CRED_REQUEST_FLAG_TO_SSO_SESSION
};

// Reimplements Windows functions that use the SSPI RPC interface
class Sspi {
public:
    // Will call LsaConnectUntrusted/SspirConnectRpc
    Sspi(const std::wstring& portName);
    // Will call LsaRegisterLogonProcess/SspirConnectRpc
    Sspi(const std::wstring& portName, const std::string& logonProcessName);
    // Will call LsaDeregisterLogonProcess/SspirDisconnectRpc
    ~Sspi();

    // Call a security package manager (SPM) API
    NTSTATUS CallSpmApi(PORT_MESSAGE* message, size_t* outputSize, void** output);

    bool Connected();

    // The authentication package APIs
    // Any returned data should be deallocated with std::free
    NTSTATUS LsaCallAuthenticationPackage(ULONG AuthenticationPackage, PVOID ProtocolSubmitBuffer, ULONG SubmitBufferLength, PVOID* ProtocolReturnBuffer, PULONG ReturnBufferLength, PNTSTATUS ProtocolStatus);
    NTSTATUS LsaLookupAuthenticationPackage(PSTRING PackageName, PULONG AuthenticationPackage);

private:
    std::wstring alpcPort{ L"lsasspirpc" }; // Default ALPC port name
    bool connected{ false };
    std::wstring logonProcessName{ L"Winlogon" }; // Default logon process name
    HANDLE lsaHandle{ nullptr };
    long operationalMode{ 0 };
    long packageCount{ 0 };
    std::unique_ptr<Rpc::Client> rpcClient{ nullptr };

    void RpcBind(const std::wstring& portName);
};

class Lsa {
public:
    std::ostream& out;

    Lsa(std::ostream& out = NullStream(), bool useRpc = true, const std::wstring& portName = std::wstring(L"lsasspirpc"));
    ~Lsa();
    bool CallPackage(const std::string& package, const std::string& submitBuffer, void** returnBuffer) const;
    // Uses the GenericPassthrough message implemented by msv1_0
    // Data will be used as an input and output argument. It's original values will be cleared if the call is successful
    bool CallPackagePassthrough(const std::wstring& domainName, const std::wstring& packageName, std::vector<byte>& data) const;
    auto Connected() {
        return connected;
    };

    // Exposes the SPM API
    // Currently only supports issuing calls via the SSPI RPC interface
    bool EnumLogonSessions() const;
    bool EnumPackages() const;

private:
    bool connected{ false };
    HANDLE lsaHandle;
    bool preNt61{ false };
    bool useBroker;
    bool useRpc;
    std::unique_ptr<Sspi> sspi;
};

void OutputHex(std::ostream& out, const std::string& data);
void OutputHex(std::ostream& out, const std::string& prompt, const std::string& data);