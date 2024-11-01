#include <Windows.h>
#include <codecvt>
#include <cxxopts.hpp>
#include <iostream>
#include <lazy.hpp>
#include <lmcons.h>
#include <locale>
#include <magic_enum/magic_enum.hpp>
#include <token.hpp>

namespace {
	typedef enum _WINSTATIONINFOCLASS {
		WinStationUserToken = 14,
	} WINSTATIONINFOCLASS;

	typedef struct _WINSTATIONUSERTOKEN {
		HANDLE ProcessId;
		HANDLE ThreadId;
		HANDLE UserToken;
	} WINSTATIONUSERTOKEN, * PWINSTATIONUSERTOKEN;

	// Available on NT 5.2 and higher
	BOOLEAN WINAPI WinStationQueryInformationW(IN HANDLE WinStationHandle, IN ULONG SessionId, IN WINSTATIONINFOCLASS WinStationInformationClass, OUT PVOID pWinStationInformation, OUT ULONG WinStationInformationLength, OUT PULONG pReturnLength);
}

namespace Token {
	void Command(Cli& cli, const std::string& args) {
		char* command{ ".token" };
		cxxopts::Options unparsedOptions{ command };
		// clang-format off
		unparsedOptions.add_options("Command arguments")
			("pid", "Process ID", cxxopts::value<long long>())
			("session", "Session ID", cxxopts::value<unsigned long>())
			("privilege", "Privilege name", cxxopts::value<std::string>())
			("disable", "Disable an privilege", cxxopts::value<bool>()->default_value("false"));
		// clang-format on

		// Tokenize the user's input
		std::vector<std::string> tokens;
		std::copy(std::istream_iterator<std::string>{ std::istringstream{ args } }, std::istream_iterator<std::string>(), std::back_inserter(tokens));
		// Construct an equivalent to argv
		std::vector<char*> argv;
		std::for_each(tokens.begin(), tokens.end(), [&argv](const std::string& arg) {
			argv.push_back(const_cast<char*>(arg.data()));
			});
		auto options{ unparsedOptions.parse(argv.size(), argv.data()) };
		if (!args.size()) {
			std::cout << unparsedOptions.help() << std::endl;
			return;
		}

		switch (magic_enum::enum_cast<SubCommands>(argv[1]).value()) {
		case SubCommands::WhoAmI:
			WhoAmI();
			break;
		case SubCommands::Impersonate:
			ImpersonateSession(options["session"].as<unsigned long>());
			break;
		case SubCommands::RevertToSelf: {
			RevertToSelf();
			break;
		}
		case SubCommands::SetPrivilege: {
			std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
			std::wstring privilege{ converter.from_bytes(options["privilege"].as<std::string>()) };
			SetPrivilege(privilege, !options["disable"].as<bool>());
			break;
		}
		default:
			break;
		}
	}

	bool ImpersonateSession(ULONG id) {
		bool succeeded{ false };
		LAZY_LOAD_LIBRARY_AND_PROC(Winsta, WinStationQueryInformationW);
		if (LazyWinsta) {
			WINSTATIONUSERTOKEN info = { 0 };
			ULONG returnLength;
			if (LazyWinStationQueryInformationW(nullptr, 1, WinStationUserToken, &info, sizeof(info), &returnLength)) {
				HANDLE impersonationToken;
				if (DuplicateTokenEx(info.UserToken, 0, nullptr, SecurityDelegation, TokenImpersonation, &impersonationToken)) {
					if (ImpersonateLoggedOnUser(impersonationToken)) {
						succeeded = true;
					}
				}
				CloseHandle(info.UserToken);
			}
			FreeLibrary(LazyWinsta);
		}
		return succeeded;
	}

	bool SetPrivilege(const std::wstring& name, bool enable, HANDLE token) {
		bool succeeded{ false };
		bool userSuppliedToken{ token != INVALID_HANDLE_VALUE };
		if (userSuppliedToken || OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token)) {
			LUID luid;
			if (LookupPrivilegeValueW(nullptr, name.data(), &luid)) {
				TOKEN_PRIVILEGES privileges;
				privileges.PrivilegeCount = 1;
				privileges.Privileges[0].Luid = luid;
				privileges.Privileges[0].Attributes = (enable) ? SE_PRIVILEGE_ENABLED : 0;
				if (AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr)) {
					succeeded = true;
				}
			}
			if (!userSuppliedToken) {
				CloseHandle(token);
			}
		}
		return succeeded;
	}

	void WhoAmI() {
		std::vector<wchar_t> userName(UNLEN + 1, L'\0');
		DWORD length{ static_cast<DWORD>(userName.size()) };
		GetUserNameW(userName.data(), &length);
		std::wcout << L"User name: " << userName.data() << std::endl;
	}
}