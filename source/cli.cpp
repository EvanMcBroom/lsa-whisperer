#include <cli.hpp>
#include <fstream>
#include <iomanip>
#include <replxx.hxx>
#include <thread>
#include <msv1_0.hpp>
#include <pku2u.hpp>
#include <schannel.hpp>
#include <memory>

using Replxx = replxx::Replxx;

namespace {
	bool Equal(std::string const& l, std::string const& r, int s) {
		if (static_cast<int>(l.length()) < s) {
			return false;
		}
		if (static_cast<int>(r.length()) < s) {
			return false;
		}
		bool same(true);
		for (int i(0); same && (i < s); ++i) {
			same = (l[i] == r[i]);
		}
		return same;
	}

	size_t WordBoundary(const char* string, bool endOffset = true) {
		size_t length{ 0 };
		for (size_t index{ 0 }; index < std::strlen(string); index++, length++) {
			if ((!endOffset && !std::strchr(Ifs, string[index])) ||
				(endOffset && std::strchr(Ifs, string[index]))
			) {
				break;
			}
		}
		return length;
	}
}

Cli::Cli(const std::string& historyFile)
	: historyFile(historyFile) {
	// Set non-default replxx preferences
	using namespace std::placeholders;
	set_completion_callback(std::bind(&Cli::CompleteContext, this, _1, _2));
	set_completion_count_cutoff(128);
	set_hint_callback(std::bind(&Cli::Hint, this, _1, _2, _3));
	set_indent_multiline(false);
	set_max_history_size(1000);
	set_prompt(this->prompt);
	set_word_break_characters(Ifs);
	// Add handler for window size changes
	install_window_change_handler();
	// load the history file if it exists
	if (!this->historyFile.empty()) {
		std::ifstream fileStream{ historyFile.c_str() };
		history_load(fileStream);
	}
	history_add(""); // Added to fix issue #137
}

void Cli::AddCommand(const std::string& name, Command command) {
	this->commands.emplace_back(name, [command](Cli& cli, const std::string& arg) {
		command(cli, arg);
		return true;
	});
}

void Cli::AddExitCommand(const std::string& name) {
	this->commands.emplace_back(name, [](Cli& cli, const std::string& arg) {
		return false;
	});
}

void Cli::AddSubCommandCompletions(const std::string& command, const std::vector<std::string>& subCommands) {
	this->subCommandCompletions[command] = subCommands;
}

void Cli::Start() {
	do {
		// Prompt the user and get their input
		const char* rawInput{ nullptr };
		do {
			rawInput = input(this->prompt);
		} while ((rawInput == nullptr) && (errno == EAGAIN));
		if (rawInput == nullptr) {
			break;
		}
		std::string input{ rawInput };
		if (input.empty()) {
			// Handle a user hitting enter after an empty line
			continue;
		}
		auto name{ input.substr(0, input.find(" ")) };
		auto item{ std::find_if(this->commands.begin(), this->commands.end(), [&name](std::pair<std::string, CommandWithResult>& item) {
			return item.first.compare(name) == 0;
		}) };
		if (item == this->commands.end()) {
			std::cout << "Command not found" << std::endl;
		}
		else if(!item->second(*this, input)) {
			// Handle if the command notified to end the repl
			break;
		}
		history_add(input);
	} while (true);
	if (!this->historyFile.empty()) {
		history_sync(this->historyFile);
	}
}

Replxx::completions_t Cli::CompleteContext(const std::string& line, int& lastWordLength) {
	Replxx::completions_t completions;
	for (auto& match : this->Matches(line)) {
		completions.emplace_back(match.data(), Replxx::Color::DEFAULT);
	}
	return completions;
}

Replxx::hints_t Cli::Hint(const std::string& line, int& lastWordLength, Replxx::Color& color) {
	Replxx::hints_t hints;
	if (lastWordLength) {
		hints = this->Matches(line);
	}
	// Set hint color to green if only a single match was found
	if (hints.size() == 1) {
		color = Replxx::Color::GREEN;
	}
	return hints;
}

std::vector<std::string> Cli::Matches(const std::string& line) {
	std::vector<std::string> matches;
	std::string firstWord{ line.substr(0, WordBoundary(line.data())) };
	if (firstWord.length() == line.length()) {
		// Gather completions for a command
		for (auto const& command : this->commands) {
			auto& name{ command.first };
			if (Equal(name, firstWord, firstWord.length())) {
				matches.emplace_back(name.data());
			}
		}
	}
	else {
		std::string remaining{ line.substr(firstWord.length(), line.length() - firstWord.length()) };
		auto secondWordStart{ WordBoundary(remaining.data(), false) };
		std::string secondWord{ remaining.substr(secondWordStart, WordBoundary(remaining.data() + secondWordStart)) };
		if ((secondWordStart + secondWord.length()) == remaining.length()) {
			// Gather completions for a sub-command
			for (auto const& subCommand : this->subCommandCompletions[firstWord]) {
				if (Equal(subCommand, secondWord, secondWord.length())) {
					matches.emplace_back(subCommand.data());
				}
			}
		}
	}
	return matches;
}