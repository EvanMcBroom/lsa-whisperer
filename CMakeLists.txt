cmake_minimum_required(VERSION 3.21.0)
project(lsa-whisperer
    VERSION "1.0"
    DESCRIPTION "A CLI for interacting with the MSV1_0"
    HOMEPAGE_URL "https://github.com/EvanMcBroom/msv1_0-cli"
    LANGUAGES CXX
)

include(cmake/ap.cmake)

find_package(cxxopts CONFIG REQUIRED)
find_package(magic_enum CONFIG REQUIRED)
find_package(pybind11 QUIET)

string(REGEX REPLACE "/M[TD]d?" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
string(REGEX REPLACE "/M[TD]d?" "" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

add_library(${PROJECT_NAME} OBJECT)

macro(add_authentication_package PACKAGE_NAME)
    add_library(${PACKAGE_NAME} STATIC)
    add_executable(${PACKAGE_NAME}-cli)
    add_executable(${PACKAGE_NAME}-dotnet)
endmacro()

add_authentication_package(msv1_0)
add_authentication_package(pku2u)
add_authentication_package(schannel)

add_subdirectory(include)
add_subdirectory(source)