#define _NTDEF_ // Required to include both Ntsecapi and Winternl
#include <Winternl.h> // Must be included before Ntsecapi
#include <Ntsecapi.h>
#include <iomanip>
#include <iostream>
#include <lsa.hpp>

UnicodeString::UnicodeString(std::wstring data) {
    RtlInitUnicodeString(this, data.c_str());
}

UnicodeString::~UnicodeString() {
    RtlFreeUnicodeString(this);
}

Lsa::Lsa(std::ostream& out)
    : out(out) {
    if (SUCCEEDED(LsaConnectUntrusted(&this->lsaHandle))) {
        connected = true;
    }
}

Lsa::~Lsa() {
    LsaDeregisterLogonProcess(lsaHandle);
}

bool Lsa::CallPackage(const std::string& package, const std::string& submitBuffer, void** returnBuffer) {
    bool result{ false };
    if (returnBuffer) {
        *returnBuffer = (void*)0x0;
        LSA_STRING packageName;
        RtlInitString(reinterpret_cast<PSTRING>(&packageName), package.data());
        ULONG authPackage;
        if (SUCCEEDED(LsaLookupAuthenticationPackage(lsaHandle, &packageName, &authPackage))) {
            PVOID returnBuffer2;
            ULONG returnBufferLength;
            NTSTATUS protocolStatus;
            OutputHex(this->out, "InputData", submitBuffer);
            auto submitBufferPtr{ submitBuffer.data() };
            auto status{ LsaCallAuthenticationPackage(lsaHandle, authPackage, reinterpret_cast<PVOID>(const_cast<char*>(submitBuffer.data())), submitBuffer.size(), &returnBuffer2, &returnBufferLength, &protocolStatus) };
            if (SUCCEEDED(status)) {
                if (protocolStatus >= 0) {
                    OutputHex(this->out, "OutputData", std::string(reinterpret_cast<const char*>(returnBuffer2), returnBufferLength));
                    *returnBuffer = returnBuffer2;
                    result = true;
                }
                else {
                    out << "OutputData[0]: nullptr" << std::endl;
                    *returnBuffer = nullptr;
                    LsaFreeReturnBuffer(returnBuffer);
                }
                out << "ProtocolStatus: 0x" << protocolStatus << std::endl << std::endl;
            }
            else {
                out << "Error: 0x" << status << std::endl;
            }
        }
        else {
            out << "Error: Could not find authentication package " << package << std::endl;
        }
    }
    return result;
}

SspiProxy::SspiProxy(const std::shared_ptr<Lsa>& lsa)
    : lsa(lsa) {

}

void OutputHex(std::ostream& out, const std::string& data) {
    for (const auto& item : data) {
        out << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(static_cast<unsigned char>(item));
    }
}

void OutputHex(std::ostream& out, const std::string& prompt, const std::string& data) {
    out << prompt << "[0x" << std::setw(2) << std::setfill('0') << std::hex << data.length() << "]: ";
    OutputHex(out, data);
    out << std::endl;
}

constexpr size_t RoundUp(size_t count, size_t powerOfTwo) {
    return (count + powerOfTwo - 1) & (~powerOfTwo - 1);
}