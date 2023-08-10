#include <appcontainer.hpp>
#include <cli.hpp>
#include <clipp.h>
#include <codecvt>
#include <commands.hpp>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <locale>
#include <magic_enum.hpp>
#include <memory>
#include <replxx.hxx>
#include <thread>
#include <token.hpp>

namespace {
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

    template<typename ProtocolMessageType>
    std::vector<std::string> SubCommands() {
        auto names{ magic_enum::enum_names<ProtocolMessageType>() };
        return std::vector<std::string>{ names.begin(), names.end() };
    }
}

int main(int argc, char** argv) {
    bool noCloudAp{ false };
    bool noHistory{ false };
    bool showHelp{ false };
    std::string brokerApp{ "./sspi-broker.exe" };
    std::string brokerPort{ "sspibroker" };
    std::string historyFile{ "./.lsa_history.txt" };
    // clang-format off
    auto args = (
        clipp::option("--broker-app").doc("Specify an alternative broker application.") & clipp::value("path", brokerApp),
        clipp::option("--broker-port").doc("Specify an alternative broker alpc port name.") & clipp::value("name", brokerPort),
        clipp::option("-h", "--help").set(showHelp).doc("Show this help message."),
        clipp::option("--history-file").doc("Specify an alternative command line history file.") & clipp::value("path", historyFile),
        clipp::option("--no-cloudap").set(noCloudAp).doc("Do not save command line history to a file."),
        clipp::option("--no-history").set(noHistory).doc("Do not create an appcontainer process for cloudap support.")
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

    Cli cli{ historyFile };
    auto lsa{ std::make_shared<Lsa>(std::cout) };

    cli.AddCommand(".clear", [](Cli& cli, const std::string& args) {
        cli.clear_screen();
    });
    cli.AddCommand(".help", Help);
    cli.AddCommand(".history", History);
    cli.AddCommand(".token", Token::Command);
    cli.AddCommand("kerberos", CommandFactory(lsa, Kerberos::Call));
    cli.AddCommand("msv1_0", CommandFactory(lsa, Msv1_0::Call));
    cli.AddCommand("negotiate", CommandFactory(lsa, Negotiate::Call));
    cli.AddCommand("pku2u", CommandFactory(lsa, Pku2u::Call));
    cli.AddCommand("schannel", CommandFactory(lsa, Schannel::Call));
    cli.AddCommand("spm", CommandFactory(lsa, Spm::Call));
    cli.AddExitCommand(".exit");
    cli.AddExitCommand(".quit");
    cli.AddSubCommandCompletions("kerberos", SubCommands<Kerberos::PROTOCOL_MESSAGE_TYPE>());
    cli.AddSubCommandCompletions("msv1_0", SubCommands<Msv1_0::PROTOCOL_MESSAGE_TYPE>());
    cli.AddSubCommandCompletions("negotiate", SubCommands<Negotiate::PROTOCOL_MESSAGE_TYPE>());
    cli.AddSubCommandCompletions("pku2u", SubCommands<Pku2u::PROTOCOL_MESSAGE_TYPE>());
    cli.AddSubCommandCompletions("schannel", SubCommands<Schannel::PROTOCOL_MESSAGE_TYPE>());
    cli.AddSubCommandCompletions("spm", SubCommands<SpmApi::NUMBER>());
    cli.AddSubCommandCompletions(".token", SubCommands<Token::SubCommands>());

    //std::unique_ptr<AppContainer> appContainer{ nullptr };
    //ProcessInfo broker{ nullptr };
    //if (!noCloudAp) {
    //    // Create the broker process in an appcontainer
    //    std::wstring name{ L"sspibroker" };
    //    std::wstring description{ L"A broker for the SSPI RPC server." };
    //    appContainer = std::make_unique<AppContainer>(name.data(), name.data(), description.data());
    //    auto converter{ std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>() };
    //    auto abroker = appContainer->CreateProcess(converter.from_bytes(brokerApp));
    //    broker = abroker.operator=;
    //    if (broker) {
    //        // Create a connection to the broker process and use if for the cloudap command
    //        auto lsa{ std::make_shared<Lsa>(std::cout, true, converter.from_bytes(brokerPort)) };
    //        cli.AddCommand("cloudap", CommandFactory(lsa, Cloudap::Call));
    //        cli.AddSubCommandCompletions("cloudap", SubCommands<Cloudap::PROTOCOL_MESSAGE_TYPE>());
    //    }
    //}

    cli.Start();
    return 0;
}