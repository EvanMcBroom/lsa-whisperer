cmake_minimum_required(VERSION 3.21.0)
project(lsa-whisperer
    VERSION "1.0"
    DESCRIPTION "A CLI for interacting with LSA"
    HOMEPAGE_URL "https://github.com/EvanMcBroom/lsa-whisperer"
    LANGUAGES CXX
)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED YES)

include(cmake/requirements.cmake)

string(REGEX REPLACE "/M[TD]d?" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
string(REGEX REPLACE "/M[TD]d?" "" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

add_library(sspi STATIC)
target_compile_definitions(sspi PUBLIC NOMINMAX)
target_link_libraries(sspi PUBLIC cxxopts::cxxopts magic_enum::magic_enum)

add_executable(lsa-whisperer)
target_sources(lsa-whisperer PRIVATE source/cli.cpp source/main.cpp)
target_link_libraries(lsa-whisperer PRIVATE replxx::replxx sspi)

add_executable(lsa-dotnet)
target_sources(lsa-dotnet PRIVATE source/cli.cpp source/main.cpp)
target_link_libraries(lsa-dotnet PRIVATE replxx::replxx sspi)
set_target_properties(lsa-dotnet PROPERTIES COMMON_LANGUAGE_RUNTIME "")

#if(pybind11_FOUND)
#    pybind11_add_module(pysspi pybindings.cpp)
#    set_target_properties(pysspi PROPERTIES
#        CXX_STANDARD 17
#        CXX_STANDARD_REQUIRED YES
#        SUFFIX .pyd
#    )
#    target_compile_definitions(pysspi PRIVATE MODULE_VERSION="${PROJECT_VERSION}")
#    target_link_libraries(pysspi PRIVATE pysspi pybind11::module)
#endif()

add_subdirectory(include)
add_subdirectory(source)