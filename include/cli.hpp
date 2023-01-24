#pragma once
#include <map>
#include <replxx.hxx>

// Internal field separator for word boundaries
char const Ifs[]{ " \t\n\r\v\f=+*&^%$#@!,/?<>;:`~'\"[]{}()|" };

class Cli : public replxx::Replxx {
public:
	using Command = std::function<void(Cli& cli, const std::string& arg)>;

	Cli(const std::string& historyFile = "");
	void AddCommand(const std::string& name, Command command);
	void AddExitCommand(const std::string& name);
	void AddSubCommandCompletions(const std::string& command, const std::vector<std::string>& subCommands);
	void Start();

private:
	using CommandWithResult = std::function<bool(Cli& cli, const std::string& arg)>;

	std::string historyFile;
	std::string prompt{ "lsa> " };
	std::vector<std::pair<std::string, CommandWithResult>> commands;
	std::map<std::string, std::vector<std::string>> subCommandCompletions;

	Replxx::completions_t CompleteContext(const std::string& line, int& lastWordLength);
	Replxx::hints_t Hint(const std::string& line, int& lastWordLength, Replxx::Color& color);
	std::vector<std::string> Matches(const std::string& line);
};