#include <lsa.hpp>
#include <iomanip>
#include <msv1_0.hpp>

namespace {
    typedef enum _THREAD_INFORMATION_CLASS {
        ThreadBasicInformation,
    } THREAD_INFORMATION_CLASS,
        *PTHREAD_INFORMATION_CLASS;

    typedef struct _THREAD_BASIC_INFORMATION {
        NTSTATUS ExitStatus;
        PVOID TebBaseAddress;
        CLIENT_ID ClientId;
        KAFFINITY AffinityMask;
        KPRIORITY Priority;
        KPRIORITY BasePriority;
    } THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

    // Based off of:
    // http://support.microsoft.com/kb/259693
    std::string FormatNtStatus(NTSTATUS status) {
        HMODULE library{ LoadLibraryW(L"NTDLL.DLL") };
        if (library) {
            LPSTR message{ nullptr };
            auto error{ RtlNtStatusToDosError(status) };
            if (FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_FROM_HMODULE, library, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPSTR>(&message), 0, nullptr)) {
                std::string messageString{ message };
                LocalFree(message);
                return messageString;
            }
            // Free loaded dll module and decrease its reference count.
            FreeLibrary(library);
        }
        return {};
    }

    std::pair<DWORD, DWORD> NtVersion() {
        auto GetDword{
            [](HKEY key, const std::wstring& subKey, const std::wstring& valueName) -> DWORD {
                DWORD value;
                DWORD size{ sizeof(decltype(value)) };
                if (RegOpenKeyW(key, subKey.data(), &key) == ERROR_SUCCESS) {
                    if (RegQueryValueExW(key, valueName.data(), nullptr, nullptr, reinterpret_cast<LPBYTE>(&value), &size) != ERROR_SUCCESS) {
                        value = -1;
                    }
                    RegCloseKey(key);
                }
                return value;
            }
        };
        DWORD majorVersion{ GetDword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"CurrentMajorVersionNumber") };
        DWORD minorVersion{ GetDword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"CurrentMinorVersionNumber") };
        return std::pair<DWORD, DWORD>(majorVersion, minorVersion);
    }
}

UnicodeString::UnicodeString(std::wstring data) {
    RtlInitUnicodeString(this, data.c_str());
}

UnicodeString::~UnicodeString() {
    RtlFreeUnicodeString(this);
}

Lsa::Lsa(std::ostream& out, bool useRpc)
    : out(out), useRpc(useRpc) {
    auto version{ NtVersion() };
    // The SSPI RPC interface is only supported on Windows 7 and above
    if (useRpc && version.first >= 6 && !(version.first == 6 && version.second == 0)) {
        this->sspi = std::make_unique<Sspi>(L"");
        this->connected = this->sspi->Connected();
    }
    // Use LSA APIs to connect if connecting via RPC failed or the host is older than Windows 7
    if (!this->connected) {
        this->useRpc = false;
        if (SUCCEEDED(LsaConnectUntrusted(&this->lsaHandle))) {
            connected = true;
        }
    }
}

Lsa::~Lsa() {
    if (!useRpc) {
        LsaDeregisterLogonProcess(lsaHandle);
    }
}

bool Lsa::CallPackage(const std::string& package, const std::string& submitBuffer, void** returnBuffer) const {
    bool result{ false };
    if (returnBuffer) {
        *returnBuffer = reinterpret_cast<void*>(0x0);
        LSA_STRING packageName;
        RtlInitString(reinterpret_cast<PSTRING>(&packageName), package.data());
        ULONG authPackage;
        NTSTATUS status;
        if (useRpc) {
            status = this->sspi->LsaLookupAuthenticationPackage(&packageName, &authPackage);
        } else {
            status = LsaLookupAuthenticationPackage(this->lsaHandle, &packageName, &authPackage);
        }
        if (SUCCEEDED(status)) {
            PVOID returnBuffer2;
            ULONG returnBufferLength;
            NTSTATUS protocolStatus;
            OutputHex(this->out, "InputData", submitBuffer);
            auto submitBufferPtr{ submitBuffer.data() };
            NTSTATUS status;
            if (useRpc) {
                status = this->sspi->LsaCallAuthenticationPackage(authPackage, reinterpret_cast<PVOID>(const_cast<char*>(submitBuffer.data())), submitBuffer.size(), &returnBuffer2, &returnBufferLength, &protocolStatus);
            } else {
                status = LsaCallAuthenticationPackage(lsaHandle, authPackage, reinterpret_cast<PVOID>(const_cast<char*>(submitBuffer.data())), submitBuffer.size(), &returnBuffer2, &returnBufferLength, &protocolStatus);
            }
            if (SUCCEEDED(status)) {
                if (protocolStatus >= 0) {
                    OutputHex(this->out, "OutputData", std::string(reinterpret_cast<const char*>(returnBuffer2), returnBufferLength));
                    *returnBuffer = returnBuffer2;
                    result = true;
                } else {
                    out << "OutputData[0]: nullptr" << std::endl;
                    *returnBuffer = nullptr;
                    LsaFreeReturnBuffer(returnBuffer);
                }
                out << "ProtocolStatus: 0x" << protocolStatus << std::endl
                    << std::endl;
            } else {
                out << "Error: 0x" << status << " - " << FormatNtStatus(status) << std::endl;
            }
        } else {
            out << "Error: Could not find authentication package " << package << std::endl;
        }
    }
    return result;
}

bool Lsa::CallPackagePassthrough(const std::wstring& domainName, const std::wstring& packageName, std::vector<byte>& data) const {
    auto requestSize{ sizeof(MSV1_0_PASSTHROUGH_REQUEST) + (domainName.size() + 1) * sizeof(wchar_t) + (packageName.size() + 1) * sizeof(wchar_t) + data.size() };

    auto request{ reinterpret_cast<Msv1_0::PASSTHROUGH_REQUEST*>(malloc(requestSize)) };
    std::memset(request, '\0', requestSize);
    request->MessageType = Msv1_0::PROTOCOL_MESSAGE_TYPE::GenericPassthrough;

    auto ptr{ reinterpret_cast<byte*>(request + 1) };
    request->DomainName.MaximumLength = request->DomainName.Length = domainName.size();
    request->DomainName.Buffer = reinterpret_cast<PWSTR>(ptr - reinterpret_cast<byte*>(request));
    std::memcpy(ptr, domainName.data(), domainName.size());

    ptr += (domainName.size() + 1) * sizeof(wchar_t);
    request->PackageName.MaximumLength = request->PackageName.Length = packageName.size();
    request->PackageName.Buffer = reinterpret_cast<PWSTR>(ptr - reinterpret_cast<byte*>(request));
    std::memcpy(ptr, packageName.data(), packageName.size());

    ptr += (packageName.size() + 1) * sizeof(wchar_t);
    request->DataLength = data.size();
    request->LogonData = reinterpret_cast<PUCHAR>(ptr - reinterpret_cast<byte*>(request));
    std::memcpy(ptr, data.data(), data.size());

    Msv1_0::PASSTHROUGH_RESPONSE* response;
    std::string stringSubmitBuffer(reinterpret_cast<const char*>(request), requestSize);
    auto result{ CallPackage(MSV1_0_PACKAGE_NAME, stringSubmitBuffer, reinterpret_cast<void**>(&response)) };
    if (result) {
        data.clear();
        data.reserve(response->DataLength);
        std::memcpy(data.data(), response->ValidationData, response->DataLength);
        LsaFreeReturnBuffer(response);
        return true;
    }
    LsaFreeReturnBuffer(response);
    return false;
}

Sspi::Sspi(const std::wstring& portName) {
    this->RpcBind(portName);
    if (this->rpcClient->IsBound()) {
        auto status{ SspirConnectRpc(nullptr, static_cast<long>(ApApi::ClientMode::Usermode), &this->packageCount, &this->operationalMode, &this->lsaHandle) };
        this->connected = NT_SUCCESS(status);
    }
}

Sspi::Sspi(const std::wstring& portName, const std::string& logonProcessName) {
    this->RpcBind(portName);
    if (this->rpcClient->IsBound() && logonProcessName.length() <= ApApi::MaxLogonProcNameLength()) {
        unsigned char message[ApApi::MaxLogonProcNameLength() + 1] = { 0 };
        std::memcpy(message, logonProcessName.data(), logonProcessName.size());
        auto status{ SspirConnectRpc(message, 0, &this->packageCount, &this->operationalMode, &this->lsaHandle) };
        this->connected = NT_SUCCESS(status);
    }
}

Sspi::~Sspi() {
    if (this->connected) {
        SspirDisconnectRpc(&this->lsaHandle);
    }
}

bool Sspi::Connected() {
    return this->connected;
}

NTSTATUS Sspi::LsaCallAuthenticationPackage(ULONG AuthenticationPackage, PVOID ProtocolSubmitBuffer, ULONG SubmitBufferLength, PVOID* ProtocolReturnBuffer, PULONG ReturnBufferLength, PNTSTATUS ProtocolStatus) {
    SpmApi::MESSAGE message = { 0 };
    message.pmMessage.u1.s1.DataLength = sizeof(message) - sizeof(PORT_MESSAGE);
    message.pmMessage.u1.s1.TotalLength = sizeof(message);
    message.ApiCallRequest.dwAPI = static_cast<SpmApi::NUMBER>(ApApi::NUMBER::CallPackageApi);
    auto& callPackage{ message.ApiCallRequest.Args.ApArguments.CallPackage };
    callPackage.AuthenticationPackage = AuthenticationPackage;
    callPackage.ProtocolSubmitBuffer = ProtocolSubmitBuffer;
    callPackage.SubmitBufferLength = SubmitBufferLength;
    size_t outputMessageSize{ 0 };
    ApApi::MESSAGE* output{ nullptr };
    auto status{ this->CallSpmApi(&message.pmMessage, &outputMessageSize, reinterpret_cast<void**>(&output)) };
    *ProtocolStatus = output->Arguments.CallPackage.ProtocolStatus;
    *ProtocolReturnBuffer = output->Arguments.CallPackage.ProtocolReturnBuffer;
    *ReturnBufferLength = output->Arguments.CallPackage.ReturnBufferLength;
    return NT_SUCCESS(status) ? output->ReturnedStatus : status;
}

NTSTATUS Sspi::LsaLookupAuthenticationPackage(PSTRING PackageName, PULONG AuthenticationPackage) {
    if (PackageName->Length <= ApApi::MaxLogonProcNameLength()) {
        SpmApi::MESSAGE message = { 0 };
        message.pmMessage.u1.s1.DataLength = sizeof(message) - sizeof(PORT_MESSAGE);
        message.pmMessage.u1.s1.TotalLength = sizeof(message);
        message.ApiCallRequest.dwAPI = static_cast<SpmApi::NUMBER>(ApApi::NUMBER::LookupPackageApi);
        auto& lookupPackage{ message.ApiCallRequest.Args.ApArguments.LookupPackage };
        lookupPackage.PackageNameLength = PackageName->Length;
        strncpy_s(lookupPackage.PackageName, ApApi::MaxLogonProcNameLength() + 1, PackageName->Buffer, PackageName->Length);
        lookupPackage.PackageName[PackageName->Length] = 0;
        size_t outputMessageSize{ 0 };
        SpmApi::MESSAGE* output{ nullptr };
        auto status{ this->CallSpmApi(&message.pmMessage, &outputMessageSize, reinterpret_cast<void**>(&output)) };
        if (NT_SUCCESS(status)) {
            *AuthenticationPackage = output->ApiCallRequest.Args.ApArguments.LookupPackage.AuthenticationPackage;
            status = output->ApiCallRequest.scRet;
            MIDL_user_free(output);
        }
        return status;
    }
    return 0xC0000106; // STATUS_NAME_TOO_LONG
}

NTSTATUS Sspi::CallSpmApi(PORT_MESSAGE* message, size_t* outputSize, void** output) {
    THREAD_BASIC_INFORMATION basicInformation = { 0 };
    auto status{ NtQueryInformationThread(GetCurrentThread(), static_cast<THREADINFOCLASS>(ThreadBasicInformation), &basicInformation, sizeof(basicInformation), nullptr) };
    if (NT_SUCCESS(status)) {
        // Only the process id is checked in lsasrv!SspiExCallRpc
        // The thread id is not actually checked, but we set it anyway to match the normal Win32 APIs
        message->ClientId.UniqueProcess = basicInformation.ClientId.UniqueProcess;
        message->ClientId.UniqueThread = basicInformation.ClientId.UniqueThread;
        *outputSize = 0;
        // Ignore the results of the outputed callback args
        // It's data is normally passed to sspicli!LsaCallbackHandler, but you can't call that
        SPMCallbackAPI args = { 0 };
        status = SspirCallRpc(this->lsaHandle, message->u1.s1.TotalLength, reinterpret_cast<unsigned char*>(message), reinterpret_cast<long*>(outputSize), reinterpret_cast<unsigned char**>(output), &args);
    }
    return status;
}

void Sspi::RpcBind(const std::wstring& portName) {
    if (portName.length()) {
        this->alpcPort = portName;
    }
    this->rpcClient = std::make_unique<Rpc::Client>(reinterpret_cast<RPC_WSTR>(this->alpcPort.data()));
    this->rpcClient->Bind(&SspiRpcImplicitHandle);
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