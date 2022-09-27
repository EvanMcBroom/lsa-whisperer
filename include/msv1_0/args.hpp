#pragma once
#include <cxxopts.hpp>
#include <msv1_0/proxy.hpp>

namespace Msv1_0 {
	bool HandleFunction(std::ostream& out, const Proxy& proxy, const cxxopts::ParseResult& result);
	void Parse(std::ostream& out, const std::vector<std::string>& args);
}