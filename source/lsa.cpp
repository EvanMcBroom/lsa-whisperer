#include <codecvt>
#include <iomanip>
#include <locale>
#include <lsa.hpp>
#include <msv1_0.hpp>
#include <string>

#define STATUS_SUCCESS 0

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

Lsa::Lsa(std::ostream& out, bool useRpc, const std::wstring& portName)
    : out(out), useBroker(useBroker) {
    auto version{ NtVersion() };
    preNt61 = version.first < 6 || (version.first == 6 && version.second == 0);
    // The SSPI RPC interface is only supported on Windows 7 and above
    this->useRpc = useRpc && !preNt61;
    if (this->useRpc) {
        this->sspi = std::make_unique<Sspi>(portName);
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


bool Lsa::CallAllPackages(const std::string& submitBuffer, void** returnBuffer, size_t* returnBufferLength) const {
    return CallPackage(SECPKG_ALL_PACKAGES, submitBuffer, returnBuffer, returnBufferLength);
}

bool Lsa::CallPackage(const std::string& package, const std::string& submitBuffer, void** returnBuffer, size_t* returnBufferLength) const {
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
            result = CallPackage(authPackage, submitBuffer, returnBuffer, returnBufferLength);
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

bool Lsa::AddCredentials() const {
    return false;
}

bool Lsa::AddPackage() const {
    return false;
}

bool Lsa::ChangeAccountPassword() const {
    return false;
}

bool Lsa::EnumLogonSessions() const {
    if (useRpc) {
        SpmApi::MESSAGE message{ SpmApi::NUMBER::EnumLogonSessions, sizeof(SpmApi::Args::SPMEnumLogonSessionAPI) };
        size_t outputMessageSize{ 0 };
        SpmApi::MESSAGE* output{ nullptr };
        auto status{ this->sspi->CallSpmApi(&message.pmMessage, &outputMessageSize, reinterpret_cast<void**>(&output)) };
        if (NT_SUCCESS(status) && SUCCEEDED(output->ApiCallRequest.scRet)) {
            auto response{ output->ApiCallRequest.Args.SpmArguments.Arguments.EnumLogonSession };
            out << "LogonSessionCount: " << response.LogonSessionCount << std::endl;
            auto luid{ reinterpret_cast<LUID*>(response.LogonSessionList) };
            for (size_t count{ response.LogonSessionCount }; count > 0; count--, luid++) {
                out << std::hex << std::setfill('0') << std::setw(8) << luid->HighPart << "-" << std::setw(8) << luid->LowPart << std::endl;
            }
            LsaFreeReturnBuffer(output);
        }
    }
    return false;
}

bool Lsa::EnumPackages() const {
    if (useRpc) {
        SpmApi::MESSAGE message{ SpmApi::NUMBER::EnumPackages, sizeof(SpmApi::Args::SPMEnumPackagesAPI) };
        size_t outputMessageSize{ 0 };
        SpmApi::MESSAGE* output{ nullptr };
        auto status{ this->sspi->CallSpmApi(&message.pmMessage, &outputMessageSize, reinterpret_cast<void**>(&output)) };
        if (NT_SUCCESS(status) && SUCCEEDED(output->ApiCallRequest.scRet)) {
            auto response{ output->ApiCallRequest.Args.SpmArguments.Arguments.EnumPackages };
            out << "Packages: " << response.cPackages << std::endl;
            auto package{ response.pPackages };
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            for (size_t count{ response.cPackages }; count > 0; count--, package++) {
                out << "Name: " << converter.to_bytes(package->Name) << std::endl;
                out << "    Capabilities: 0x" << std::setfill('0') << std::setw(8) << package->fCapabilities << std::endl;
                out << "    Version     : " << package->wVersion << std::endl;
                out << "    RPCID       : " << package->wRPCID << std::endl;
                out << "    MaxToken    : " << package->cbMaxToken << std::endl;
                out << "    Comment     : " << converter.to_bytes(package->Comment) << std::endl;
            }
            LsaFreeReturnBuffer(output);
        }
    }
    return false;
}

bool Lsa::FindPackage(const std::wstring& name) const {
    if (useRpc) {
        SpmApi::MESSAGE message{ SpmApi::NUMBER::FindPackage, sizeof(SpmApi::Args::SPMFindPackageAPI) };
        auto& data{ message.ApiCallRequest.bData };
        std::memcpy(data, name.data(), name.size() * sizeof(wchar_t));
        auto& packageName{ message.ApiCallRequest.Args.SpmArguments.Arguments.FindPackage.ssPackageName };
        packageName.Length = static_cast<unsigned short>(name.length());
        packageName.MaximumLength = static_cast<unsigned short>(name.length() + 1);
        packageName.Buffer = reinterpret_cast<LPWSTR>(data);
        size_t outputMessageSize{ 0 };
        SpmApi::MESSAGE* output{ nullptr };
        auto status{ this->sspi->CallSpmApi(&message.pmMessage, &outputMessageSize, reinterpret_cast<void**>(&output)) };
        if (NT_SUCCESS(status) && SUCCEEDED(output->ApiCallRequest.scRet)) {
            auto response{ output->ApiCallRequest.Args.SpmArguments.Arguments.FindPackage };
            out << "PackageId: 0x" << std::setfill('0') << std::setw(8) << response.ulPackageId << std::endl;
            LsaFreeReturnBuffer(output);
        }
    }
    return false;
}

bool Lsa::GetBinding() const {
    return false;
}

bool Lsa::GetLogonSessionData(PLUID luid) const {
    if (useRpc) {
        SpmApi::MESSAGE message{ SpmApi::NUMBER::GetLogonSessionData, sizeof(SpmApi::Args::SPMGetUserInfoAPI) };
        auto& data{ message.ApiCallRequest.bData };
        message.ApiCallRequest.Args.SpmArguments.Arguments.GetLogonSessionData.LogonId.LowPart = luid->LowPart;
        message.ApiCallRequest.Args.SpmArguments.Arguments.GetLogonSessionData.LogonId.HighPart = luid->HighPart;
        size_t outputMessageSize{ 0 };
        SpmApi::MESSAGE* output{ nullptr };
        auto status{ this->sspi->CallSpmApi(&message.pmMessage, &outputMessageSize, reinterpret_cast<void**>(&output)) };
        if (NT_SUCCESS(status) && SUCCEEDED(output->ApiCallRequest.scRet)) {
            auto response{ output->ApiCallRequest.Args.SpmArguments.Arguments.GetLogonSessionData.LogonSessionInfo };
            if (response) {
                auto session{ reinterpret_cast<PSECURITY_LOGON_SESSION_DATA>(response) };
                std::wcout << L"LogonId              : 0x" << std::hex << std::setfill(L'0') << std::setw(4) << session->LogonId.LowPart << std::endl;
                std::wcout << L"UserName             : " << std::wstring(session->UserName.Buffer, session->UserName.Buffer + (session->UserName.Length / sizeof(wchar_t))) << std::endl;
                std::wcout << L"LogonDomain          : " << std::wstring(session->LogonDomain.Buffer, session->LogonDomain.Buffer + (session->LogonDomain.Length / sizeof(wchar_t))) << std::endl;
                std::wcout << L"AuthenticationPackage: " << std::wstring(session->AuthenticationPackage.Buffer, session->AuthenticationPackage.Buffer + (session->AuthenticationPackage.Length / sizeof(wchar_t))) << std::endl;
                std::wcout << L"LogonType            : " << session->LogonType << std::endl;
                std::wcout << L"Session              : " << session->Session << std::endl;
                UNICODE_STRING sidString;
                if (RtlConvertSidToUnicodeString(&sidString, session->Sid, true) == STATUS_SUCCESS) {
                    std::wcout << L"Sid                  : " << sidString.Buffer << std::endl;
                    RtlFreeUnicodeString(&sidString);
                }
                std::wcout << L"LogonTime            : 0x" << std::hex << std::setfill(L'0') << std::setw(4) << session->LogonTime.QuadPart << std::endl;
                std::wcout << L"LogonServer          : " << std::wstring(session->LogonServer.Buffer, session->LogonServer.Buffer + (session->LogonServer.Length / sizeof(wchar_t))) << std::endl;
                std::wcout << L"DnsDomainName        : " << std::wstring(session->DnsDomainName.Buffer, session->DnsDomainName.Buffer + (session->DnsDomainName.Length / sizeof(wchar_t))) << std::endl;
                std::wcout << L"Upn                  : " << std::wstring(session->Upn.Buffer, session->Upn.Buffer + (session->Upn.Length / sizeof(wchar_t))) << std::endl;
                std::wcout << L"UserFlags            : " << session->UserFlags << std::endl;
                std::wcout << L"LastLogonInfo" << std::endl;
                std::wcout << L"    LastSuccessfulLogon: 0x" << std::hex << std::setfill(L'0') << std::setw(4) << session->LastLogonInfo.LastSuccessfulLogon.QuadPart << std::endl;
                std::wcout << L"    LastFailedLogon    : 0x" << std::hex << std::setfill(L'0') << std::setw(4) << session->LastLogonInfo.LastFailedLogon.QuadPart << std::endl;
                std::wcout << L"    FailedAttemptCount : " << session->LastLogonInfo.FailedAttemptCountSinceLastSuccessfulLogon << std::endl;
                std::wcout << L"LogonScript          : " << std::wstring(session->LogonScript.Buffer, session->LogonScript.Buffer + (session->LogonScript.Length / sizeof(wchar_t))) << std::endl;
                std::wcout << L"ProfilePath          : " << std::wstring(session->ProfilePath.Buffer, session->ProfilePath.Buffer + (session->ProfilePath.Length / sizeof(wchar_t))) << std::endl;
                std::wcout << L"HomeDirectory        : " << std::wstring(session->HomeDirectory.Buffer, session->HomeDirectory.Buffer + (session->HomeDirectory.Length / sizeof(wchar_t))) << std::endl;
                std::wcout << L"HomeDirectoryDrive   : " << std::wstring(session->HomeDirectoryDrive.Buffer, session->HomeDirectoryDrive.Buffer + (session->HomeDirectoryDrive.Length / sizeof(wchar_t))) << std::endl;
                std::wcout << L"LogoffTime           : 0x" << std::hex << std::setfill(L'0') << std::setw(8) << session->LogoffTime.QuadPart << std::endl;
                std::wcout << L"KickOffTime          : 0x" << std::hex << std::setfill(L'0') << std::setw(8) << session->KickOffTime.QuadPart << std::endl;
                std::wcout << L"PasswordLastSet      : 0x" << std::hex << std::setfill(L'0') << std::setw(8) << session->PasswordLastSet.QuadPart << std::endl;
                std::wcout << L"PasswordCanChange    : 0x" << std::hex << std::setfill(L'0') << std::setw(8) << session->PasswordCanChange.QuadPart << std::endl;
                std::wcout << L"PasswordMustChange   : 0x" << std::hex << std::setfill(L'0') << std::setw(8) << session->PasswordMustChange.QuadPart << std::endl;
                LsaFreeReturnBuffer(response);
            }
            LsaFreeReturnBuffer(output);
        }
    }
    return false;
}

bool Lsa::GetUserInfo(PLUID luid) const {
    if (useRpc) {
        SpmApi::MESSAGE message{ SpmApi::NUMBER::GetUserInfo, sizeof(SpmApi::Args::SPMGetUserInfoAPI) };
        auto& data{ message.ApiCallRequest.bData };
        message.ApiCallRequest.Args.SpmArguments.Arguments.GetUserInfo.LogonId.LowPart = luid->LowPart;
        message.ApiCallRequest.Args.SpmArguments.Arguments.GetUserInfo.LogonId.HighPart = luid->HighPart;
        size_t outputMessageSize{ 0 };
        SpmApi::MESSAGE* output{ nullptr };
        auto status{ this->sspi->CallSpmApi(&message.pmMessage, &outputMessageSize, reinterpret_cast<void**>(&output)) };
        if (NT_SUCCESS(status) && SUCCEEDED(output->ApiCallRequest.scRet)) {
            auto response{ output->ApiCallRequest.Args.SpmArguments.Arguments.GetUserInfo.pUserInfo };
            std::wcout << L"UserName       : " << std::wstring(response->UserName.Buffer, response->UserName.Buffer + (response->UserName.Length / sizeof(wchar_t))) << std::endl;
            std::wcout << L"LogonDomainName: " << std::wstring(response->LogonDomainName.Buffer, response->LogonDomainName.Buffer + (response->LogonDomainName.Length / sizeof(wchar_t))) << std::endl;
            std::wcout << L"LogonServer    : " << std::wstring(response->LogonServer.Buffer, response->LogonServer.Buffer + (response->LogonServer.Length / sizeof(wchar_t))) << std::endl;
            UNICODE_STRING sidString;
            if (RtlConvertSidToUnicodeString(&sidString, response->pSid, true) == STATUS_SUCCESS) {
                std::wcout << L"Sid            : " << sidString.Buffer << std::endl;
                RtlFreeUnicodeString(&sidString);
            }
            LsaFreeReturnBuffer(output);
        }
    }
    return false;
}

bool Lsa::LookupAccountName() const {
    return false;
}

bool Lsa::LookupWellKnownSid() const {
    return false;
}

bool Lsa::LsaPolicyChangeNotify() const {
    return false;
}

bool Lsa::QueryContextAttributes() const {
    return false;
}

bool Lsa::QueryCredAttributes() const {
    return false;
}

bool Lsa::QueryPackage(const std::wstring& name) const {
    if (useRpc) {
        SpmApi::MESSAGE message{ SpmApi::NUMBER::QueryPackage, sizeof(SpmApi::Args::SPMQueryPackageAPI) };
        auto& data{ message.ApiCallRequest.bData };
        std::memset(data, '\0', sizeof(data));
        auto& packageName{ message.ApiCallRequest.Args.SpmArguments.Arguments.QueryPackage.ssPackageName };
        packageName.Length = static_cast<unsigned short>(name.length());
        packageName.MaximumLength = static_cast<unsigned short>(name.length() + 1);
        packageName.Buffer = reinterpret_cast<LPWSTR>(data);
        size_t outputMessageSize{ 0 };
        SpmApi::MESSAGE* output{ nullptr };
        auto status{ this->sspi->CallSpmApi(&message.pmMessage, &outputMessageSize, reinterpret_cast<void**>(&output)) };
        if (NT_SUCCESS(status) && SUCCEEDED(output->ApiCallRequest.scRet)) {
            auto response{ output->ApiCallRequest.Args.SpmArguments.Arguments.QueryPackage.pPackageInfo };
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            out << "Capabilities: 0x" << std::setfill('0') << std::setw(8) << response->fCapabilities << std::endl;
            out << "Version     : " << response->wVersion << std::endl;
            out << "RPCID       : " << response->wRPCID << std::endl;
            out << "MaxToken    : " << response->cbMaxToken << std::endl;
            out << "Name        : " << response->Name << std::endl;
            out << "Comment     : " << converter.to_bytes(response->Comment) << std::endl;
            LsaFreeReturnBuffer(output);
        }
    }
    return false;
}

bool Lsa::SetContextAttributes() const {
    return false;
}

bool Lsa::SetCredAttributes() const {
    return false;
}

bool Lsa::SetSession() const {
    return false;
}

bool Lsa::CallPackage(ULONG package, const std::string& submitBuffer, void** returnBuffer, size_t* returnBufferLength) const {
    bool result{ false };
    PVOID returnBuffer2;
    ULONG returnBufferLength2;
    NTSTATUS protocolStatus;
    OutputHex(this->out, "InputData", submitBuffer);
    auto submitBufferPtr{ submitBuffer.data() };
    NTSTATUS status;
    if (useRpc) {
        status = this->sspi->LsaCallAuthenticationPackage(package, reinterpret_cast<PVOID>(const_cast<char*>(submitBuffer.data())), submitBuffer.size(), &returnBuffer2, &returnBufferLength2, &protocolStatus);
    } else {
        status = LsaCallAuthenticationPackage(lsaHandle, package, reinterpret_cast<PVOID>(const_cast<char*>(submitBuffer.data())), submitBuffer.size(), &returnBuffer2, &returnBufferLength2, &protocolStatus);
    }
    if (SUCCEEDED(status)) {
        if (protocolStatus >= 0) {
            OutputHex(this->out, "OutputData", std::string(reinterpret_cast<const char*>(returnBuffer2), returnBufferLength2));
            *returnBuffer = returnBuffer2;
            if (returnBufferLength) {
                *returnBufferLength = returnBufferLength2;
            }
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
    return result;
}

Sspi::Sspi(const std::wstring& portName) {
    this->RpcBind(portName);
    if (this->rpcClient->IsBound()) {
        auto status{ SspirConnectRpc(nullptr, static_cast<long>(AuApi::ClientMode::Usermode), &this->packageCount, &this->operationalMode, &this->lsaHandle) };
        this->connected = NT_SUCCESS(status);
    }
}

Sspi::Sspi(const std::wstring& portName, const std::string& logonProcessName) {
    this->RpcBind(portName);
    if (this->rpcClient->IsBound() && logonProcessName.length() <= AuApi::MaxLogonProcNameLength()) {
        unsigned char message[AuApi::MaxLogonProcNameLength() + 1] = { 0 };
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
        SSPIR_SPMCallbackAPI args = { 0 };
        status = SspirCallRpc(this->lsaHandle, message->u1.s1.TotalLength, reinterpret_cast<unsigned char*>(message), reinterpret_cast<long*>(outputSize), reinterpret_cast<unsigned char**>(output), &args);
    }
    return status;
}

bool Sspi::Connected() {
    return this->connected;
}

NTSTATUS Sspi::LsaCallAuthenticationPackage(ULONG AuthenticationPackage, PVOID ProtocolSubmitBuffer, ULONG SubmitBufferLength, PVOID* ProtocolReturnBuffer, PULONG ReturnBufferLength, PNTSTATUS ProtocolStatus) {
    AuApi::MESSAGE message{ AuApi::NUMBER::CallPackage };
    auto& callPackage{ message.Arguments.CallPackage };
    callPackage.AuthenticationPackage = AuthenticationPackage;
    callPackage.ProtocolSubmitBuffer = ProtocolSubmitBuffer;
    callPackage.SubmitBufferLength = SubmitBufferLength;
    size_t outputMessageSize{ 0 };
    AuApi::MESSAGE* output{ nullptr };
    auto status{ this->CallSpmApi(&message.pmMessage, &outputMessageSize, reinterpret_cast<void**>(&output)) };
    *ProtocolStatus = output->Arguments.CallPackage.ProtocolStatus;
    *ProtocolReturnBuffer = output->Arguments.CallPackage.ProtocolReturnBuffer;
    *ReturnBufferLength = output->Arguments.CallPackage.ReturnBufferLength;
    return NT_SUCCESS(status) ? output->ReturnedStatus : status;
}

NTSTATUS Sspi::LsaLookupAuthenticationPackage(PSTRING PackageName, PULONG AuthenticationPackage) {
    if (PackageName->Length <= AuApi::MaxLogonProcNameLength()) {
        AuApi::MESSAGE message{ AuApi::NUMBER::LookupPackage };
        auto& lookupPackage{ message.Arguments.LookupPackage };
        lookupPackage.PackageNameLength = PackageName->Length;
        strncpy_s(lookupPackage.PackageName, AuApi::MaxLogonProcNameLength() + 1, PackageName->Buffer, PackageName->Length);
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