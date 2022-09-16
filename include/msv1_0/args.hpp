#pragma once
#include <cxxopts.hpp>
#include <msv1_0/proxy.hpp>

namespace Msv1_0 {
	bool HandleFunction(const Proxy& proxy, const cxxopts::ParseResult& result);
	bool Parse(int argc, char** argv);
}