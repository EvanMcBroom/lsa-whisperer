#pragma once
#include <cxxopts.hpp>
#include <schannel/proxy.hpp>

namespace Schannel {
	bool HandleFunction(std::ostream& out, const Proxy& proxy, const cxxopts::ParseResult& result);
	void Parse(std::ostream& out, const std::vector<std::string>& args);
}