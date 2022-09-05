cmake_minimum_required(VERSION 3.16.3)
project(msv1_0-cli
    VERSION "1.0"
    DESCRIPTION "A CLI for interacting with the MSV1_0"
    HOMEPAGE_URL "https://github.com/EvanMcBroom/msv1_0-cli"
    LANGUAGES CXX
)
find_package(cxxopts CONFIG REQUIRED)
find_package(magic_enum CONFIG REQUIRED)

string(REGEX REPLACE "/M[TD]d?" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
string(REGEX REPLACE "/M[TD]d?" "" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

add_executable(msv1_0-cli cache.cpp crypt.cpp main.cpp msv1_0.cpp)
target_link_libraries(msv1_0-cli PRIVATE cxxopts::cxxopts magic_enum::magic_enum)
set_target_properties(msv1_0-cli PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
)

add_subdirectory(include)