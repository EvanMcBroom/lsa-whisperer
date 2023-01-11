#include <cli.hpp>
#include <fstream>
#include <iomanip>
#include <replxx.hxx>
#include <msv1_0.hpp>
#include <pku2u.hpp>
#include <schannel.hpp>
#include <memory>
#include <thread>

namespace {
	void Help(Cli& cli, const std::string& args) {
		std::cout << "Please refer to the wiki for information about specific commands:" << std::endl
		<< "https://github.com/EvanMcBroom/lsa-whisperer/wiki" << std::endl;
	}

	template<typename Function>
	auto HandlerFactory(Function function) {
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
}

int main(int argc_, char** argv_) {
	Cli cli{ "./.lsa_history.txt" };
	cli.AddCommand(".clear", [](Cli& cli, const std::string& args) {
		cli.clear_screen();
	});
	cli.AddCommand(".help", Help);
	cli.AddCommand(".history", History);
	cli.AddCommand("msv1_0", HandlerFactory(Msv1_0::Parse));
	cli.AddCommand("pku2u", HandlerFactory(Pku2u::Parse));
	cli.AddCommand("schannel", HandlerFactory(Schannel::Parse));
	cli.AddExitCommand(".exit");
	cli.AddExitCommand(".quit");
	cli.Start();



	return 0;
}