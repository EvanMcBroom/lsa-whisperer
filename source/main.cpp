#include <cli.hpp>
#include <clipp.h>
#include <codecvt>
#include <commands.hpp>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <locale>
#include <magic_enum/magic_enum.hpp>
#include <memory>
#include <replxx.hxx>
#include <thread>
#include <token.hpp>
#include <wininet.h>

namespace {
    // https://gist.github.com/EvanMcBroom/2a9bed888c2755153a9616aa7ae1f79a
    template<typename _T>
    unsigned int constexpr Hash(_T const* input) {
        return *input ? static_cast<unsigned int>(*input) + 33 * Hash(input + 1) : 5381;
    }

    void Help(Cli& cli, const std::string& args) {
        std::cout << "Please refer to the wiki for information about specific commands:" << std::endl
                  << "https://github.com/EvanMcBroom/lsa-whisperer/wiki" << std::endl;
    }

    template<typename PackageCall>
    auto CommandFactory(const std::shared_ptr<Lsa>& lsa, PackageCall packageCall) {
        return [lsa, packageCall](Cli& cli, const std::string& input) {
            // Tokenize the user's input
            std::istringstream inputStream{ input };
            std::vector<std::string> tokens;
            std::copy(std::istream_iterator<std::string>(inputStream), std::istream_iterator<std::string>(), std::back_inserter(tokens));
            // Construct an equivalent to argv
            std::vector<char*> argv;
            std::for_each(tokens.begin(), tokens.end(), [&argv](const std::string& arg) {
                argv.push_back(const_cast<char*>(arg.data()));
            });
            try {
                packageCall(lsa, argv);
            } catch (const std::exception& exception) {
                std::cout << exception.what() << std::endl;
            }
        };
    }

    void History(Cli& cli, const std::string& args) {
        auto scan{ cli.history_scan() };
        for (size_t i{ 0 }; scan.next(); i++) {
            std::cout << std::setw(4) << i << ": " << scan.get().text() << std::endl;
        }
    }

    void Nonce(Cli& cli, const std::string& args) {
        auto internet{ InternetOpenW(L"", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0) };
        if (internet) {
            auto connection{ InternetConnectW(internet, L"login.microsoftonline.com", 443, nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0) };
            if (connection) {
                DWORD flags{ INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_NO_AUTO_REDIRECT | INTERNET_FLAG_NO_UI | INTERNET_FLAG_SECURE };
                auto request{ HttpOpenRequestW(connection, L"POST", L"/common/oauth2/token", nullptr, nullptr, nullptr, flags, 0) };
                if (request) {
                    std::string body{ "grant_type=srv_challenge" };
                    if (HttpSendRequestW(request, nullptr, 0, body.data(), body.length())) {
                        DWORD status{ 0 };
                        DWORD bufferLength{ sizeof(status) };
                        if (HttpQueryInfoW(request, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &status, &bufferLength, 0)) {
                            // A post response may not contain a content length header
                            // So do not refer to it when reading all bytes from the body of the POST response
                            size_t chunkSize{ 1024 };
                            std::vector<std::vector<byte>> chunks;
                            DWORD bytesRead{ 0 };
                            size_t totalRead{ 0 };
                            do {
                                // On additional iterations of the loop, resize the previously recieved chunk is necessary
                                if (chunks.size()) {
                                    chunks.back().resize(bytesRead);
                                }
                                chunks.emplace_back(std::vector<byte>(chunkSize, 0));
                                totalRead += bytesRead;
                            } while (InternetReadFile(request, chunks.back().data(), chunkSize, &bytesRead) && bytesRead);
                            if (totalRead) {
                                // Using chunk size intervals when coalescing data to make the process easier to write
                                std::vector<byte> buffer(chunks.size() * chunkSize, 0);
                                size_t bytesCopied{ 0 };
                                for (size_t index{ 0 }; index < chunks.size(); index++) {
                                    auto& chunk{ chunks[index] };
                                    std::memcpy(buffer.data() + bytesCopied, chunk.data(), chunk.size());
                                    bytesCopied += chunk.size();
                                }
                                std::wstring response{ buffer.data(), buffer.data() + buffer.size() };
                                std::wcout << response << std::endl;
                            }
                        }
                    }
                    InternetCloseHandle(request);
                }
                InternetCloseHandle(connection);
            }
            InternetCloseHandle(internet);
        }
    }

    template<typename ProtocolMessageType>
    std::vector<std::string> SubCommands() {
        auto names{ magic_enum::enum_names<ProtocolMessageType>() };
        return std::vector<std::string>{ names.begin(), names.end() };
    }
}

int main(int argc, char** argv) {
    bool noHistory{ false };
    bool showHelp{ false };
    std::string historyFile{ "./.lsa_history.txt" };
    std::vector<std::string> commands;
    // clang-format off
    auto args = (
        clipp::option("-h", "--help").set(showHelp).doc("Show this help message."),
        clipp::option("--history-file").doc("Specify an alternative command line history file.") & clipp::value("path", historyFile),
        clipp::option("--no-history").set(noHistory).doc("Do not create a command line history file."),
        clipp::opt_values("command", commands)
    );
    // clang-format on
    clipp::parse(argc, argv, args);
    if (showHelp) {
        std::cout << clipp::make_man_page(args) << std::endl;
        return 0;
    }
    if (noHistory) {
        historyFile.clear();
    }
    auto lsa{ std::make_shared<Lsa>(std::cout) };
    if (!commands.empty()) {
        // Process each commands
        for (auto& command : commands) {
            std::istringstream inputStream{ command };
            std::vector<std::string> tokens;
            std::copy(std::istream_iterator<std::string>(inputStream), std::istream_iterator<std::string>(), std::back_inserter(tokens));
            // Construct an equivalent to argv
            std::vector<char*> argv;
            std::for_each(tokens.begin(), tokens.end(), [&argv](const std::string& arg) {
                argv.push_back(const_cast<char*>(arg.data()));
            });
            // Pass the command to the appropriate handler
            switch (Hash(argv[0])) {
            case Hash("all"): AllPackages::Call(lsa, argv); break;
            case Hash("cloudap"): Cloudap::Call(lsa, argv); break;
            case Hash("kerberos"): Kerberos::Call(lsa, argv); break;
            case Hash("live"): Live::Call(lsa, argv); break;
            case Hash("msv1_0"): Msv1_0::Call(lsa, argv); break;
            case Hash("negoexts"): Negoexts::Call(lsa, argv); break;
            case Hash("negotiate"): Negotiate::Call(lsa, argv); break;
            case Hash("pku2u"): Pku2u::Call(lsa, argv); break;
            case Hash("schannel"): Schannel::Call(lsa, argv); break;
            case Hash("spm"): Spm::Call(lsa, argv); break;
            default:
                break;
            }
        }
    } else {
        // Start repl shell
        Cli cli{ historyFile };

        cli.AddCommand(".clear", [](Cli& cli, const std::string& args) {
            cli.clear_screen();
        });
        cli.AddCommand(".help", Help);
        cli.AddCommand(".history", History);
        cli.AddCommand(".nonce", Nonce);
        cli.AddCommand(".token", Token::Command);
        cli.AddCommand("all", CommandFactory(lsa, AllPackages::Call));
        cli.AddCommand("cloudap", CommandFactory(lsa, Cloudap::Call));
        cli.AddCommand("kerberos", CommandFactory(lsa, Kerberos::Call));
        cli.AddCommand("live", CommandFactory(lsa, Live::Call));
        cli.AddCommand("msv1_0", CommandFactory(lsa, Msv1_0::Call));
        cli.AddCommand("negoexts", CommandFactory(lsa, Negoexts::Call));
        cli.AddCommand("negotiate", CommandFactory(lsa, Negotiate::Call));
        cli.AddCommand("pku2u", CommandFactory(lsa, Pku2u::Call));
        cli.AddCommand("schannel", CommandFactory(lsa, Schannel::Call));
        cli.AddCommand("spm", CommandFactory(lsa, Spm::Call));
        cli.AddExitCommand(".exit");
        cli.AddExitCommand(".quit");
        // Add autocompletions for each command's subcommands
        cli.AddSubCommandCompletions("all", SubCommands<AllPackages::PROTOCOL_MESSAGE_TYPE>());
        // Cloudap's subcommands are also handled directly to add the plugin commands for AAD
        auto cloudapPluginFunctions{ magic_enum::enum_names<Cloudap::Aad::CALL>() };
        auto cloudapMessages(magic_enum::enum_names<Cloudap::PROTOCOL_MESSAGE_TYPE>());
        std::vector<std::string> cloudapSubCommands{ cloudapMessages.begin(), cloudapMessages.end() };
        cloudapSubCommands.insert(cloudapSubCommands.end(), cloudapPluginFunctions.begin(), cloudapPluginFunctions.end());
        cloudapSubCommands.erase(std::remove(cloudapSubCommands.begin(), cloudapSubCommands.end(), "CreateBindingKey"), cloudapSubCommands.end());
        cloudapSubCommands.erase(std::remove(cloudapSubCommands.begin(), cloudapSubCommands.end(), "GenerateBindingClaims"), cloudapSubCommands.end());
        cli.AddSubCommandCompletions("cloudap", cloudapSubCommands);
        cli.AddSubCommandCompletions("kerberos", SubCommands<Kerberos::PROTOCOL_MESSAGE_TYPE>());
        cli.AddSubCommandCompletions("live", SubCommands<Live::PROTOCOL_MESSAGE_TYPE>());
        cli.AddSubCommandCompletions("msv1_0", SubCommands<Msv1_0::PROTOCOL_MESSAGE_TYPE>());
        cli.AddSubCommandCompletions("negoexts", SubCommands<Negoexts::PROTOCOL_MESSAGE_TYPE>());
        cli.AddSubCommandCompletions("negotiate", SubCommands<Negotiate::PROTOCOL_MESSAGE_TYPE>());
        cli.AddSubCommandCompletions("pku2u", SubCommands<Pku2u::PROTOCOL_MESSAGE_TYPE>());
        cli.AddSubCommandCompletions("schannel", SubCommands<Schannel::PROTOCOL_MESSAGE_TYPE>());
        cli.AddSubCommandCompletions("spm", SubCommands<SpmApi::NUMBER>());
        cli.AddSubCommandCompletions(".token", SubCommands<Token::SubCommands>());

        cli.Start();
    }
    return 0;
}