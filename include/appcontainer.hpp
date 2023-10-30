#include <Windows.h>
#include <memory>
#include <string>
#undef CreateProcess

class ProcessInfo;

class AppContainer {
public:
    AppContainer(const std::wstring& name, const std::wstring& displayName, const std::wstring& description);
    ~AppContainer();

    // Create a process in the app container. Made for creating a broker for the SSPI RPC server
    // This is supported because cloudap requires the calling RPC client to have the userSigninSupport capability
    void CreateProcess(const std::wstring& app);
    bool Started();

private:
    std::wstring appContainerName;
    PSID appContainerSid{ nullptr };
    bool createdProfile{ false };
    bool initializedSid{ false };
};

class ProcessInfo : public std::unique_ptr<PROCESS_INFORMATION> {
public:
    ~ProcessInfo();
};