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
	size_t CodepointCount(const uint8_t* bytes, size_t byteCount) {
		size_t codepointCount{ 0 };
		for (size_t index{ 0 }; index < byteCount; index++, codepointCount++) {
			auto codepoint{ bytes + index };
			auto firstByte{ *codepoint };
			if (firstByte & 0x80) {
				index += ((firstByte & 0xF0) >> 6) - 1;
			}
		}
		return codepointCount;
	}

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

	size_t LastWordLength(const char* string) {
		size_t length{ 0 };
		for (size_t index{ std::strlen(string) - 1 }; index >= 0; index--, length++) {
			if (std::strchr(Ifs, string[index])) {
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
	history_add(""); // Added to fix issues #137
	// Deletion keybindings
	bind_key_internal(Replxx::KEY::BACKSPACE, "delete_character_left_of_cursor");
	bind_key_internal(Replxx::KEY::DELETE, "delete_character_under_cursor");
	bind_key_internal(Replxx::KEY::control('W'), "kill_to_begining_of_word");
	bind_key_internal(Replxx::KEY::control('U'), "kill_to_begining_of_line");
	bind_key_internal(Replxx::KEY::control('K'), "kill_to_end_of_line");
	bind_key_internal(Replxx::KEY::meta(Replxx::KEY::BACKSPACE), "kill_to_whitespace_on_left");
	bind_key_internal(Replxx::KEY::meta('d'), "kill_to_end_of_word");
	// Navigation keybindings
	bind_key_internal(Replxx::KEY::LEFT, "move_cursor_left");
	bind_key_internal(Replxx::KEY::RIGHT, "move_cursor_right");
	bind_key_internal(Replxx::KEY::HOME, "move_cursor_to_begining_of_line");
	bind_key_internal(Replxx::KEY::END, "move_cursor_to_end_of_line");
	bind_key_internal(Replxx::KEY::control(Replxx::KEY::LEFT), "move_cursor_one_word_left");
	bind_key_internal(Replxx::KEY::control(Replxx::KEY::RIGHT), "move_cursor_one_word_right");
	bind_key_internal(Replxx::KEY::control(Replxx::KEY::ENTER), "commit_line");
	bind_key_internal(Replxx::KEY::INSERT, "toggle_overwrite_mode");
	// History keybindings
	// bind_key_internal(Replxx::KEY::UP, "line_previous");
	// bind_key_internal(Replxx::KEY::DOWN, "line_next");
	// bind_key_internal(Replxx::KEY::meta(Replxx::KEY::UP), "history_previous");
	// bind_key_internal(Replxx::KEY::meta(Replxx::KEY::DOWN), "history_next");
	// bind_key_internal(Replxx::KEY::PAGE_UP, "history_first");
	// bind_key_internal(Replxx::KEY::PAGE_DOWN, "history_last");
	// bind_key_internal(Replxx::KEY::control('R'), "history_incremental_search");
	// bind_key_internal(Replxx::KEY::meta('p'), "history_common_prefix_search");
	// bind_key_internal(Replxx::KEY::meta('n'), "history_common_prefix_search");
	// Completion keybindings
	bind_key_internal(Replxx::KEY::TAB, "complete_line");
	bind_key_internal(Replxx::KEY::control(Replxx::KEY::UP), "hint_previous");
	bind_key_internal(Replxx::KEY::control(Replxx::KEY::DOWN), "hint_next");
	// Vim keybindings
	bind_key_internal(Replxx::KEY::control('Y'), "yank");
	bind_key_internal(Replxx::KEY::meta('y'), "yank_cycle");
	bind_key_internal(Replxx::KEY::control('L'), "clear_screen");
	bind_key_internal(Replxx::KEY::control('D'), "send_eof");
	bind_key_internal(Replxx::KEY::control('C'), "abort_line");
	bind_key_internal(Replxx::KEY::control('T'), "transpose_characters");
	bind_key_internal(Replxx::KEY::meta('u'), "uppercase_word");
	bind_key_internal(Replxx::KEY::meta('l'), "lowercase_word");
	bind_key_internal(Replxx::KEY::meta('c'), "capitalize_word");
	bind_key_internal('a', "insert_character");
}

void Cli::AddCommand(const std::string name, Command command) {
	this->commands.emplace_back(name, [command](Cli& cli, const std::string& arg) {
		command(cli, arg);
		return true;
	});
}

void Cli::AddExitCommand(const std::string name) {
	this->commands.emplace_back(name, [](Cli& cli, const std::string& arg) {
		return false;
	});
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

Replxx::completions_t Cli::CompleteContext(const std::string& context, int& contextLength) {
	auto lastWordLength{ LastWordLength(context.data()) };
	auto prefixLength{ context.length() - lastWordLength };
	if ((prefixLength > 0) && (context[prefixLength - 1] == '\\')) {
		--prefixLength;
		++lastWordLength;
	}
	std::string prefix{ context.substr(prefixLength) };
	Replxx::completions_t completions;
	for (auto const& command : commands) {
		auto& name{ command.first };
		if (Equal(name, prefix, lastWordLength)) {
			Replxx::Color c(Replxx::Color::DEFAULT);
			if (name.find("brightred") != std::string::npos) {
				c = Replxx::Color::BRIGHTRED;
			}
			else if (name.find("red") != std::string::npos) {
				c = Replxx::Color::RED;
			}
			completions.emplace_back(name.c_str(), c);
		}
	}
	contextLength = CodepointCount(reinterpret_cast<const uint8_t*>(context.data() + prefixLength), lastWordLength);
	return completions;
}

Replxx::hints_t Cli::Hint(const std::string& context, int& contextLength, Replxx::Color& color) {
	auto lastWordLength{ LastWordLength(context.data()) };
	auto prefixLength{ context.length() - lastWordLength };
	std::string lastWord{ context.substr(prefixLength, lastWordLength) };
	Replxx::hints_t hints;
	if (!lastWord.empty()) {
		for (auto const& command : commands) {
			auto& name{ command.first };
			if (Equal(name, lastWord, lastWord.size())) {
				hints.emplace_back(name.c_str());
			}
		}
	}
	// Set hint color to green if only a single match was found
	if (hints.size() == 1) {
		color = Replxx::Color::GREEN;
	}
	contextLength = CodepointCount(reinterpret_cast<const uint8_t*>(context.data() + prefixLength), lastWordLength);
	return hints;
}