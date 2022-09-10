function(target_ap_sources)
    # Process the function's arguments
    set(OPTIONS)
    set(ONE_VALUE_ARGS TARGET)
    set(MULTI_VALUE_ARGS SOURCES)
    cmake_parse_arguments(AP "${OPTIONS}" "${ONE_VALUE_ARGS}" "${MULTI_VALUE_ARGS}" ${ARGN})

    # Check that the user supplied the required arguments and that SOURCES is not empty
    if (${ARGC} LESS 1)
        message(FATAL_ERROR "Argument 1, target not specified")
    else()
        list(LENGTH AP_SOURCES NUMBER_OF_SOURCES)
        if(${NUMBER_OF_SOURCES} EQUAL 0)
            message(FATAL_ERROR "Argument SOURCES does not have any values.")
        endif()
    endif()
    set(AP_TARGET ${ARGV0})

    target_sources(${AP_TARGET} PRIVATE ${AP_SOURCES})

    target_link_libraries(${AP_TARGET} PUBLIC $<TARGET_OBJECTS:${PROJECT_NAME}> $<TARGET_PROPERTY:${PROJECT_NAME},LINK_LIBRARIES> cxxopts::cxxopts magic_enum::magic_enum Ntdll.lib Secur32.lib)
    target_compile_definitions(${AP_TARGET} PRIVATE NOMINMAX)
    target_include_directories(${AP_TARGET} PUBLIC $<TARGET_PROPERTY:${PROJECT_NAME},INCLUDE_DIRECTORIES>)
    set_target_properties(${AP_TARGET} PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED YES
    )
    
    target_sources(${AP_TARGET}-cli PRIVATE ${AP_TARGET}/main.cpp)
    target_link_libraries(${AP_TARGET}-cli PRIVATE ${AP_TARGET})
    
    target_sources(${AP_TARGET}-dotnet PRIVATE ${AP_TARGET}/main.cpp)
    target_link_libraries(${AP_TARGET}-dotnet PRIVATE ${AP_TARGET})
    set_target_properties(${AP_TARGET}-dotnet PROPERTIES COMMON_LANGUAGE_RUNTIME "")
    
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
endfunction()