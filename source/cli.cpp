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
	int ContextLength(char const* prefix) {
		int length{ 0 };
		for (size_t index{ std::strlen(prefix) - 1 }; index >= 0; index--, length++) {
			if (std::strchr(Ifs, prefix[length]) != NULL) {
				break;
			}
		}
		return length;
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

	int Utf8CodepointLength(char const* s, int utf8len) {
		int codepointLen = 0;
		unsigned char m4{ 128 + 64 + 32 + 16 };
		unsigned char m3{ 128 + 64 + 32 };
		unsigned char m2{ 128 + 64 };
		for (int i{ 0 }; i < utf8len; ++i, ++codepointLen) {
			char c = s[i];
			if ((c & m4) == m4) {
				i += 3;
			}
			else if ((c & m3) == m3) {
				i += 2;
			}
			else if ((c & m2) == m2) {
				i += 1;
			}
		}
		return codepointLen;
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

void Cli::AddCommand(const std::string name, CommandWithResult command) {
	this->commands.emplace_back(name, command);
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
			// Handle if the command was not successful or it notified to end the repl
			break;
		}
		history_add(input);
	} while (true);
	if (!this->historyFile.empty()) {
		history_sync(this->historyFile);
	}
}

Replxx::completions_t Cli::CompleteContext(const std::string& context, int& contextLength) {
	Replxx::completions_t completions;
	int utf8ContextLen(ContextLength(context.c_str()));
	int prefixLen(static_cast<int>(context.length()) - utf8ContextLen);
	if ((prefixLen > 0) && (context[prefixLen - 1] == '\\')) {
		--prefixLen;
		++utf8ContextLen;
	}
	contextLength = Utf8CodepointLength(context.c_str() + prefixLen, utf8ContextLen);

	std::string prefix{ context.substr(0, prefixLen) };
	for (auto const& command : commands) {
		auto& name{ command.first };
		bool lowerCasePrefix(std::none_of(prefix.begin(), prefix.end(), iswupper));
		if (Equal(command.first, prefix, static_cast<int>(prefix.size()))) {
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
	return completions;
}

Replxx::hints_t Cli::Hint(const std::string& context, int& contextLength, Replxx::Color& color) {
	int utf8ContextLength(ContextLength(context.data()));
	auto prefixLen{ context.length() - utf8ContextLength };
	contextLength = Utf8CodepointLength(context.data() + prefixLen, utf8ContextLength);
	std::string prefix{ context.substr(0, prefixLen) };
	// Only show hint if prefix is at least 'n' chars long
	// or if prefix begins with a specific character
	Replxx::hints_t hints;
	if (prefix.size() >= 2 || (!prefix.empty() && prefix.at(0) == '.')) {
		for (auto const& command : commands) {
			auto& name{ command.first };
			if (Equal(name, prefix, prefix.size())) {
				hints.emplace_back(name.c_str());
			}
		}
	}
	// Set hint color to green if single match found
	if (hints.size() == 1) {
		color = Replxx::Color::GREEN;
	}

	return hints;
}