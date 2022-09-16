#pragma once
#include <cxxopts.hpp>
#include <pku2u/proxy.hpp>

namespace Pku2u {
	bool HandleFunction(const Proxy& proxy, const cxxopts::ParseResult& result);
	bool Parse(int argc, char** argv);
}