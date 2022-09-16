cmake_minimum_required(VERSION 3.21.0)
project(lsa-whisperer
    VERSION "1.0"
    DESCRIPTION "A CLI for interacting with LSA"
    HOMEPAGE_URL "https://github.com/EvanMcBroom/lsa-whisperer"
    LANGUAGES CXX
)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED YES)

find_package(cxxopts CONFIG REQUIRED)
find_package(magic_enum CONFIG REQUIRED)
find_package(pybind11 QUIET)

string(REGEX REPLACE "/M[TD]d?" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
string(REGEX REPLACE "/M[TD]d?" "" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

add_library(core STATIC)
target_compile_definitions(core PUBLIC NOMINMAX)

macro(add_authentication_package PACKAGE_NAME)
    add_library(${PACKAGE_NAME} STATIC)
    target_link_libraries(${PACKAGE_NAME} PUBLIC core cxxopts::cxxopts magic_enum::magic_enum)
    list(APPEND AUTHENTICATION_PACKAGES ${PACKAGE_NAME})
endmacro()

add_authentication_package(msv1_0)
add_authentication_package(pku2u)
add_authentication_package(schannel)

add_executable(lsa-whisperer)
target_sources(lsa-whisperer PRIVATE source/main.cpp)
target_link_libraries(lsa-whisperer PRIVATE ${AUTHENTICATION_PACKAGES})

add_executable(lsa-dotnet)
target_sources(lsa-dotnet PRIVATE source/main.cpp)
target_link_libraries(lsa-dotnet PRIVATE ${AUTHENTICATION_PACKAGES})
set_target_properties(lsa-dotnet PROPERTIES COMMON_LANGUAGE_RUNTIME "")

#if(pybind11_FOUND)
#    pybind11_add_module(py${AP_TARGET} pybindings.cpp)
#    set_target_properties(py${AP_TARGET} PROPERTIES
#        CXX_STANDARD 17
#        CXX_STANDARD_REQUIRED YES
#        SUFFIX .pyd
#    )
#    target_compile_definitions(py${AP_TARGET} PRIVATE MODULE_VERSION="${PROJECT_VERSION}")
#    target_link_libraries(py${AP_TARGET} PRIVATE msv1_0 pybind11::module)
#endif()

add_subdirectory(include)
add_subdirectory(source)