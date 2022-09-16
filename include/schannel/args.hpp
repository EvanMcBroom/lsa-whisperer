#pragma once
#include <cxxopts.hpp>
#include <schannel/proxy.hpp>

namespace Schannel {
	bool HandleFunction(const Proxy& proxy, const cxxopts::ParseResult& result);
	bool Parse(int argc, char** argv);
}