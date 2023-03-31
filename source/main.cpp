#include <cli.hpp>
#include <commands.hpp>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <magic_enum.hpp>
#include <memory>
#include <replxx.hxx>
#include <thread>

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

int main(int argc_, char** argv_) {
    Cli cli{ "./.lsa_history.txt" };
    auto lsa{ std::make_shared<Lsa>(std::cout) };

    cli.AddCommand(".clear", [](Cli& cli, const std::string& args) {
        cli.clear_screen();
    });
    cli.AddCommand(".help", Help);
    cli.AddCommand(".history", History);
    cli.AddCommand("cloudap", CommandFactory(lsa, Cloudap::Call));
    cli.AddCommand("kerberos", CommandFactory(lsa, Kerberos::Call));
    cli.AddCommand("msv1_0", CommandFactory(lsa, Msv1_0::Call));
    cli.AddCommand("negotiate", CommandFactory(lsa, Negotiate::Call));
    cli.AddCommand("pku2u", CommandFactory(lsa, Pku2u::Call));
    cli.AddCommand("schannel", CommandFactory(lsa, Schannel::Call));
    cli.AddExitCommand(".exit");
    cli.AddExitCommand(".quit");
    cli.AddSubCommandCompletions("cloudap", SubCommands<Cloudap::PROTOCOL_MESSAGE_TYPE>());
    cli.AddSubCommandCompletions("kerberos", SubCommands<Kerberos::PROTOCOL_MESSAGE_TYPE>());
    cli.AddSubCommandCompletions("msv1_0", SubCommands<Msv1_0::PROTOCOL_MESSAGE_TYPE>());
    cli.AddSubCommandCompletions("negotiate", SubCommands<Negotiate::PROTOCOL_MESSAGE_TYPE>());
    cli.AddSubCommandCompletions("pku2u", SubCommands<Pku2u::PROTOCOL_MESSAGE_TYPE>());
    cli.AddSubCommandCompletions("schannel", SubCommands<Schannel::PROTOCOL_MESSAGE_TYPE>());
    cli.Start();
    return 0;
}