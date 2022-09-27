#pragma once
#include <cxxopts.hpp>
#include <pku2u/proxy.hpp>

namespace Pku2u {
	bool HandleFunction(std::ostream& out, const Proxy& proxy, const cxxopts::ParseResult& result);
	void Parse(std::ostream& out, const std::vector<std::string>& args);
}