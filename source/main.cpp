#include <cli.hpp>
#include <cli/clilocalsession.h>
#include <cli/filehistorystorage.h>
#include <cli/loopscheduler.h>
#include <msv1_0/args.hpp>
#include <pku2u/args.hpp>
#include <schannel/args.hpp>
#include <memory>

// Used because cli::Menu::Insert throws an error if the functions are used directly
template<typename Function>
auto HandlerFactory(Function function) {
    return [function](std::ostream& out, const std::vector<std::string>& args) {
        function(std::forward<std::ostream&>(out), std::forward<const std::vector<std::string>&>(args));
    };
}

void App(const std::string& log) {
    cli::SetColor();

    auto rootMenu{ std::make_unique<cli::Menu>("lsa") };

    auto sspiMenu{ std::make_unique<cli::Menu>("sspi") };
    sspiMenu->Insert("msv1_0", HandlerFactory(Msv1_0::Parse));
    sspiMenu->Insert("pku2u", HandlerFactory(Pku2u::Parse));
    sspiMenu->Insert("schannel", HandlerFactory(Schannel::Parse));
    rootMenu->Insert(std::move(sspiMenu));

    auto cli{
        (!log.length())
        ? cli::Cli(std::move(rootMenu), std::make_unique<cli::VolatileHistoryStorage>())
        : cli::Cli(std::move(rootMenu), std::make_unique<cli::FileHistoryStorage>(log))
    };
    cli.ExitAction([](auto& out) { out << "Disconnecting...\n"; });
    cli.StdExceptionHandler([](std::ostream& out, const std::string& cmd, const std::exception& exception) {
        out << "Exception caught in lsa handler: " << exception.what() << " handling command: " << cmd << "." << std::endl;
     });

    cli::LoopScheduler scheduler;
    cli::CliLocalSession localSession(cli, scheduler, std::cout, 200);
    localSession.ExitAction([&scheduler](auto& out) {
        out << "Closing App...\n";
        scheduler.Stop();
    });
    scheduler.Run();
}

int main(int argc, char** argv) {
    cxxopts::Options options{ "lsa-whisperer" };

    options.add_options()
        ("h,help", "Print usage")
        ("l,log", "Log commands", cxxopts::value<bool>()->default_value("false"))
        ;

    std::string log{ "" };
    try {
        auto result{ options.parse(argc, argv) };
        if (result.count("help")) {
            std::cout << options.help() << std::endl;
            return 0;
        }
        if (result.count("log")) {
            log = "lw_history.txt";
        };
    }
    catch (const std::exception& exception) {
        std::cout << exception.what() << std::endl;
    }

    App(log);
    return 0;
}