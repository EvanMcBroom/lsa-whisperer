#pragma once
#include <Windows.h>
#include <cli.hpp>
#include <string>

namespace Token {
    enum class SubCommands {
        Impersonate,
        RevertToSelf,
        SetPrivilege,
        WhoAmI,
    };

    void Command(Cli& cli, const std::string& args);

    bool ImpersonateSession(ULONG id);

    bool SetPrivilege(const std::wstring& name, bool enable = true, HANDLE token = INVALID_HANDLE_VALUE);

    void WhoAmI();
}