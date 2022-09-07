cmake_minimum_required(VERSION 3.21.0)
project(lsa-whisperer
    VERSION "1.0"
    DESCRIPTION "A CLI for interacting with the MSV1_0"
    HOMEPAGE_URL "https://github.com/EvanMcBroom/msv1_0-cli"
    LANGUAGES CXX
)
find_package(cxxopts CONFIG REQUIRED)
find_package(magic_enum CONFIG REQUIRED)
find_package(pybind11 QUIET)

string(REGEX REPLACE "/M[TD]d?" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
string(REGEX REPLACE "/M[TD]d?" "" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

add_library(msv1_0 OBJECT args.cpp cache.cpp crypt.cpp msv1_0.cpp)
target_link_libraries(msv1_0 PUBLIC cxxopts::cxxopts magic_enum::magic_enum)
target_compile_definitions(msv1_0 PRIVATE NOMINMAX)
set_target_properties(msv1_0 PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
)

add_executable(msv1_0-cli main.cpp)
target_link_libraries(msv1_0-cli PRIVATE $<TARGET_OBJECTS:msv1_0>)
target_include_directories(msv1_0-cli PRIVATE $<TARGET_PROPERTY:msv1_0,INCLUDE_DIRECTORIES>)

add_executable(msv1_0-dotnet main.cpp)
target_link_libraries(msv1_0-dotnet PRIVATE $<TARGET_OBJECTS:msv1_0>)
set_target_properties(msv1_0-dotnet PROPERTIES COMMON_LANGUAGE_RUNTIME "")
target_include_directories(msv1_0-dotnet PRIVATE $<TARGET_PROPERTY:msv1_0,INCLUDE_DIRECTORIES>)

if(pybind11_FOUND)
    # Disable "Link Time Optimization" while adding the python module to have CMake export it's symbols on Windows:
    # https://pybind11.readthedocs.io/en/stable/compiling.html
    # This requires either calling pybind11_add_module with the argument NO_EXTRAS or using add_library and linking pybind11::module
    add_library(pymsv1_0 SHARED pybindings.cpp)
    set_target_properties(pymsv1_0 PROPERTIES
        WINDOWS_EXPORT_ALL_SYMBOLS ON
        OUTPUT_NAME pymsv1_0
        PREFIX "${PYTHON_MODULE_PREFIX}"
        SUFFIX "${PYTHON_MODULE_EXTENSION}"
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED YES
    )
    target_link_libraries(pymsv1_0 PRIVATE $<TARGET_OBJECTS:msv1_0> pybind11::module)
    target_include_directories(pymsv1_0 PRIVATE $<TARGET_PROPERTY:msv1_0,INCLUDE_DIRECTORIES>)
endif()

add_subdirectory(include)