#include <appcontainer.hpp>
#include <userenv.h>

AppContainer::AppContainer(const std::wstring& name, const std::wstring& displayName, const std::wstring& description)
    : appContainerName(name) {
    if (SUCCEEDED(CreateAppContainerProfile(name.data(), name.data(), description.data(), nullptr, 0, &appContainerSid))) {
        createdProfile = true;
        initializedSid = true;
    }
    if (SUCCEEDED(DeriveAppContainerSidFromAppContainerName(name.data(), &appContainerSid))) {
        initializedSid = true;
    }
}

AppContainer::~AppContainer() {
    if (initializedSid) {
        FreeSid(appContainerSid);
    }
    if (createdProfile) {
        DeleteAppContainerProfile(appContainerName.data());
    }
}


// Code is based on:
// https://medium.com/that-feeling-when-it-is-compiler-fault/appcontainers-for-windows-8-what-are-they-and-how-can-you-create-them-e5970a28eea4
void AppContainer::CreateProcess(const std::wstring& app) {
    if (initializedSid) {
        //STARTUPINFOEX si = { sizeof(si) };
        //PROCESS_INFORMATION pi;
        //SIZE_T size;
        //SECURITY_CAPABILITIES sc = { 0 };
        //sc.AppContainerSid = appContainerSid;
        //::InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
        //BYTE buffer[size] = { 0 };
        //si.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(buffer);
        //::InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size));
        //::UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &sc, sizeof(sc), nullptr, nullptr));
        //
        //
        //
        //STARTUPINFOW startupInfo = { sizeof(STARTUPINFOW) };
        //startupInfo.dwFlags = STARTF_USESHOWWINDOW;
        //startupInfo.wShowWindow = SW_HIDE;
        //SECURITY_CAPABILITIES sc = { 0 };
        //sc.AppContainerSid = appContainerSid;
        //InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
        //BYTE buffer[size] = { 0 };
        //startupInfo.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(buffer);
        //InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);
        //UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &sc, sizeof(sc), nullptr, nullptr));
        //auto processInfo{ std::make_unique<PROCESS_INFORMATION>() };
        //return CreateProcessW(brokerApp.data(), nullptr, nullptr, nullptr, false, CREATE_NO_WINDOW, nullptr, nullptr, &startupInfo, processInfo.get()) ? std::move(processInfo) : nullptr;
    }
    return;
}

bool AppContainer::Started() {
    return initializedSid;
}

ProcessInfo::~ProcessInfo() {
    if (this->get()) {
        CloseHandle((*this)->hThread);
        CloseHandle((*this)->hProcess);
    }
}