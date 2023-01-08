#pragma once
#include <replxx.hxx>

// Internal field separator for word boundaries
char const Ifs[]{ " \t\n\r\v\f=+*&^%$#@!,/?<>;:`~'\"[]{}()|" };

class Cli : public replxx::Replxx {
public:
	using Command = std::function<void(Cli& cli, const std::string& arg)>;
	using CommandWithResult = std::function<bool(Cli& cli, const std::string& arg)>;

	Cli(const std::string& historyFile = "");
	void AddCommand(const std::string name, Command command);
	void AddCommand(const std::string name, CommandWithResult command);
	void Start();

private:
	std::string historyFile;
	std::string prompt{ "lsa> " };
	std::vector<std::pair<std::string, CommandWithResult>> commands;

	Replxx::completions_t CompleteContext(const std::string& context, int& contextLength);
	Replxx::hints_t Hint(const std::string& context, int& contextLength, Replxx::Color& color);
};