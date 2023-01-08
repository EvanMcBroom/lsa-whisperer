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
		std::cout
			<< ".help\n\tdisplays the help output\n"
			<< ".quit\n\texit the repl\n"
			<< ".exit\n\texit the repl\n"
			<< ".clear\n\tclears the screen\n"
			<< ".history\n\tdisplays the history output\n"
			<< ".prompt <str>\n\tset the repl prompt to <str>\n";
	}

	void History(Cli& cli, const std::string& args) {
		auto scan{ cli.history_scan() };
		for (size_t i{ 0 }; scan.next(); i++) {
			std::cout << std::setw(4) << i << ": " << scan.get().text() << std::endl;
		}
	}
}

int main(int argc_, char** argv_) {
	std::vector<std::string> examples{
		".help", ".history", ".quit", ".exit", ".clear", ".prompt ",
		"hello", "world", "db", "data", "drive", "print", "put",
		"determinANT", "determiNATION", "deterMINE", "deteRMINISM", "detERMINISTIC", "deTERMINED",
		"star", "star_galaxy_cluser_supercluster_observable_universe",
	};

	auto exitCommand{ [](Cli& cli, const std::string& arg) {
		return false;
	} };
	Cli cli{ "./.lsa_history.txt" };
	cli.AddCommand(".clear", [](Cli& cli, const std::string& args) {
		cli.clear_screen();
	});
	cli.AddCommand(".exit", (Cli::CommandWithResult)exitCommand);
	cli.AddCommand(".help", Help);
	cli.AddCommand(".history", History);
	cli.AddCommand(".quit", (Cli::CommandWithResult)exitCommand);
	cli.Start();
	return 0;
}


//void App(const std::string& log) {
//    cli::SetColor();
//
//    auto rootMenu{ std::make_unique<cli::Menu>("lsa") };
//
//    auto sspiMenu{ std::make_unique<cli::Menu>("sspi") };
//    sspiMenu->Insert("msv1_0", HandlerFactory(Msv1_0::Parse));
//    sspiMenu->Insert("pku2u", HandlerFactory(Pku2u::Parse));
//    sspiMenu->Insert("schannel", HandlerFactory(Schannel::Parse));
//    rootMenu->Insert(std::move(sspiMenu));
//
//    auto cli{
//        (!log.length())
//        ? cli::Cli(std::move(rootMenu), std::make_unique<cli::VolatileHistoryStorage>())
//        : cli::Cli(std::move(rootMenu), std::make_unique<cli::FileHistoryStorage>(log))
//    };
//    cli.ExitAction([](auto& out) { out << "Disconnecting...\n"; });
//    cli.StdExceptionHandler([](std::ostream& out, const std::string& cmd, const std::exception& exception) {
//        out << "Exception caught in lsa handler: " << exception.what() << " handling command: " << cmd << "." << std::endl;
//     });
//
//    cli::LoopScheduler scheduler;
//    cli::CliLocalSession localSession(cli, scheduler, std::cout, 200);
//    localSession.ExitAction([&scheduler](auto& out) {
//        out << "Closing App...\n";
//        scheduler.Stop();
//    });
//    scheduler.Run();
//}
//
//int main(int argc, char** argv) {
//    cxxopts::Options options{ "lsa-whisperer" };
//
//    options.add_options()
//        ("h,help", "Print usage")
//        ("l,log", "Log commands", cxxopts::value<bool>()->default_value("false"))
//        ;
//
//    std::string log{ "" };
//    try {
//        auto result{ options.parse(argc, argv) };
//        if (result.count("help")) {
//            std::cout << options.help() << std::endl;
//            return 0;
//        }
//        if (result.count("log")) {
//            log = "lw_history.txt";
//        };
//    }
//    catch (const std::exception& exception) {
//        std::cout << exception.what() << std::endl;
//    }
//
//    App(log);
//    return 0;
//}