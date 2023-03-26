#include <cloudap.hpp>
#include <cli.hpp>
#include <fstream>
#include <iomanip>
#include <replxx.hxx>
#include <msv1_0.hpp>
#include <negotiate.hpp>
#include <pku2u.hpp>
#include <schannel.hpp>
#include <kerberos.hpp>
#include <magic_enum.hpp>
#include <memory>
#include <thread>

namespace {
	void Help(Cli& cli, const std::string& args) {
		std::cout << "Please refer to the wiki for information about specific commands:" << std::endl
		<< "https://github.com/EvanMcBroom/lsa-whisperer/wiki" << std::endl;
	}

	template<typename Function>
	auto CommandFactory(Function function) {
		return [function](Cli& cli, const std::string& args) {
			std::istringstream argStream{ args };
			std::vector<std::string> tokens;
			std::copy(std::istream_iterator<std::string>(argStream), std::istream_iterator<std::string>(), std::back_inserter(tokens));
			function(std::cout, tokens);
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
	cli.AddCommand(".clear", [](Cli& cli, const std::string& args) {
		cli.clear_screen();
	});
	cli.AddCommand(".help", Help);
	cli.AddCommand(".history", History);
	cli.AddCommand("cloudap", CommandFactory(Cloudap::Parse));
    cli.AddCommand("msv1_0", CommandFactory(Msv1_0::Parse));
    cli.AddCommand("negotiate", CommandFactory(Negotiate::Parse));
	cli.AddCommand("pku2u", CommandFactory(Pku2u::Parse));
	cli.AddCommand("schannel", CommandFactory(Schannel::Parse));
    cli.AddCommand("kerberos", CommandFactory(Kerberos::Parse));
	cli.AddExitCommand(".exit");
	cli.AddExitCommand(".quit");
	cli.AddSubCommandCompletions("cloudap", SubCommands<Cloudap::PROTOCOL_MESSAGE_TYPE>());
    cli.AddSubCommandCompletions("msv1_0", SubCommands<Msv1_0::PROTOCOL_MESSAGE_TYPE>());
    cli.AddSubCommandCompletions("negotiate", SubCommands<Negotiate::PROTOCOL_MESSAGE_TYPE>());
	cli.AddSubCommandCompletions("pku2u", SubCommands<Pku2u::PROTOCOL_MESSAGE_TYPE>());
	cli.AddSubCommandCompletions("schannel", SubCommands<Schannel::PROTOCOL_MESSAGE_TYPE>());
    cli.AddSubCommandCompletions("kerberos", SubCommands<Kerberos::PROTOCOL_MESSAGE_TYPE>());
	cli.Start();
	return 0;
}