cmake_minimum_required(VERSION 3.21.0)
project(lsa-whisperer
    VERSION "2.1"
    DESCRIPTION "A CLI for interacting with LSA"
    HOMEPAGE_URL "https://github.com/EvanMcBroom/lsa-whisperer"
    LANGUAGES CXX
)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})
include(cmake/midl.cmake)
include(cmake/requirements.cmake)

add_library(sspi STATIC)
target_compile_definitions(sspi PUBLIC NOMINMAX)
target_link_libraries(sspi PUBLIC magic_enum::magic_enum)

add_executable(lsa-whisperer)
target_link_libraries(lsa-whisperer PRIVATE advapi32 Userenv.lib Wininet.lib clipp::clipp cxxopts::cxxopts magic_enum::magic_enum replxx::replxx sspi)

add_subdirectory(include)
add_subdirectory(source)

find_package(Doxygen QUIET)
if(DOXYGEN_FOUND)
    set(DOXYGEN_PROJECT_NAME "SSPI Library")
    set(DOXYGEN_PROJECT_BRIEF "The library used by lsa-whisperer to interact with LSA")
    set(DOXYGEN_EXTRACT_ANON_NSPACES NO)
    set(DOXYGEN_QUIET YES)
    set(DOXYGEN_WARN_IF_INCOMPLETE_DOC NO)
    set(DOXYGEN_WARN_IF_UNDOCUMENTED NO)
    set(DOXYGEN_OUTPUT_DIRECTORY docs/doxygen)
    set(DOXYGEN_GENERATE_XML YES)
    doxygen_add_docs(docs-doxygen
        ${SSPI_HEADERS}
        ${SSPI_SOURCES}
        ALL USE_STAMP_FILE
        COMMENT "Generating Doxygen docs"
    )
    # Add sphinx doc generation as a seperate command,
    # not a post build command for the doxygen doc generation
    # because the required python modules may not be installed
    find_package(Breathe QUIET)
    find_package(Sphinx QUIET)
    if (BREATHE_FOUND AND SPHINX_FOUND)
        add_custom_target(docs-sphinx
            COMMAND ${SPHINX_EXECUTABLE}
                -b html
                -Drelease=${PROJECT_VERSION}
                -Dbreathe_projects.SspiLibrary=${CMAKE_CURRENT_BINARY_DIR}/docs/doxygen/xml
                ${CMAKE_CURRENT_BINARY_DIR}/docs/sphinx/rst ${CMAKE_CURRENT_BINARY_DIR}/docs/sphinx/html
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Generating Sphinx docs"
        )
        add_custom_command(TARGET docs-sphinx PRE_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_SOURCE_DIR}/docs ${CMAKE_CURRENT_BINARY_DIR}/docs/sphinx/rst
            COMMENT "Copying docs directory to RST directory"
        )
        add_custom_command(TARGET docs-sphinx PRE_BUILD
            COMMAND ${BREATHE_APIDOC_EXECUTABLE} -o ${CMAKE_CURRENT_BINARY_DIR}/docs/sphinx/rst ${CMAKE_CURRENT_BINARY_DIR}/docs/doxygen/xml
            COMMENT "Converting Doxygen XML to RSTs"
        )
        add_dependencies(docs-sphinx docs-doxygen)
        set_target_properties(docs-sphinx PROPERTIES EXCLUDE_FROM_ALL TRUE)
        install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/docs/sphinx/html DESTINATION docs)
    else()
        install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/docs/doxygen/html DESTINATION docs)
    endif()
endif()