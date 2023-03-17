# Copyright (C) 2022 Evan McBroom

#! target_idl_sources : Add idl sources to a target.
#
# target_idl_sources(<target> <CLIENT|SERVER> [items1...])
#
# Specifies idl sources to use when building a target.
# The named <target> must have been created by a command such as add_executable() or add_library() or add_custom_target() and must not be an ALIAS target.
# The <items> may use generator expressions.
#
# The CLIENT and SERVER keywords are required to specify the type of stubs to build from the source file paths (<items>) that follow them.
# All generated stubs will be PRIVATE scoped when added to the target.
# 
# \arg:target the first argument
# \arg:stub_type must be CLIENT or SERVER
# \group:items a list of idl files to add
#
function(target_idl_sources)
    # Process the function's arguments
    set(OPTIONS)
    set(ONE_VALUE_ARGS TARGET)
    set(MULTI_VALUE_ARGS SOURCES)
    cmake_parse_arguments(MIDL "${OPTIONS}" "${ONE_VALUE_ARGS}" "${MULTI_VALUE_ARGS}" ${ARGN})

    # Check that the user supplied the required arguments and that SOURCES is not empty
    if (${ARGC} LESS 1)
        message(FATAL_ERROR "Argument 1, target not specified")
    elseif(NOT (${ARGV1} STREQUAL "CLIENT") AND NOT (${ARGV1} STREQUAL "SERVER"))
        message(FATAL_ERROR "Argument 2, stub type must be CLIENT or SERVER")
    else()
        list(LENGTH MIDL_SOURCES NUMBER_OF_SOURCES)
        if(${NUMBER_OF_SOURCES} EQUAL 0)
            message(FATAL_ERROR "Argument SOURCES does not have any values.")
        endif()
    endif()
    set(MIDL_TARGET ${ARGV0})
    set(MIDL_STUB_TYPE ${ARGV1})


    set(IDL_FILES
        # You need to include the MS-DTYP IDL to allow the include statements in the other IDL file to resolve correctly
        # You will need to later overwrite the generated ms-dtyp.h file because it will redefine Windows base types
        ${CMAKE_CURRENT_FUNCTION_LIST_DIR}/ms-dtyp.idl
        ${MIDL_SOURCES}
    )

    # We will generate a batch file with a midl command to run for each source idl file to pass to CMake's execute_process function
    set(MIDL_BATCH_FILE ${CMAKE_CURRENT_BINARY_DIR}/midl_commands_for_${MIDL_TARGET}.bat)
    set(MIDL_BATCH_FILE_CONTENT)
    set(MIDL_OUTPUT_FILES)
    if(${CMAKE_VS_PLATFORM_NAME} STREQUAL "x64")
        set(MIDL_ENV "amd64")
        set(MIDL_ARCH "x64")
    else()
        set(MIDL_ENV "win32")
        set(MIDL_ARCH "x86")
    endif()

    # Get the midl compiler location. This method supports all versions of the Windows 10 and 11 SDKs
    get_filename_component(WINDOWS_SDK_DIR "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Kits\\Installed Roots;KitsRoot10]" ABSOLUTE)
    set(MIDL_PATH ${WINDOWS_SDK_DIR}/bin/${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}/${MIDL_ARCH}/midl.exe)

    # Set the midl compiler options for the stub type
    if(${MIDL_STUB_TYPE} STREQUAL "CLIENT")
        set(MIDL_STUB_OPTIONS "/client stub /server none")
        set(MIDL_STUB_SUFFIX "_c")
    else()
        set(MIDL_STUB_OPTIONS "/client none /server stub")
        set(MIDL_STUB_SUFFIX "_s")
    endif()

    # Populate the MIDL_BATCH_FILE_CONTENT variable
    foreach(FILE IN ITEMS ${IDL_FILES})
        get_filename_component(FILE_NAME ${FILE} NAME_WE) # Option NAME_WE will remove the .idl extension
        set(FILE_NAME ${FILE_NAME}${MIDL_STUB_SUFFIX}) # Add a client/server suffix to avoid stubs from overwritten each other
        set(MIDL_BATCH_FILE_CONTENT
            ${MIDL_BATCH_FILE_CONTENT}
            # https://docs.microsoft.com/en-us/windows/win32/midl/midl-command-line-reference
            # Note: These RPC stubs use a C extension. Your CMake project or target MUST include the C
            # language for these stubs to participate builds
            "\"${MIDL_PATH}\" /app_config /env ${MIDL_ENV} /W1 /char signed /target \"NT61\" ${MIDL_STUB_OPTIONS} /nologo "
            "/cstub \"${CMAKE_CURRENT_BINARY_DIR}/${FILE_NAME}.c\" "
            "/sstub \"${CMAKE_CURRENT_BINARY_DIR}/${FILE_NAME}.c\" "
            "/h \"${CMAKE_CURRENT_BINARY_DIR}/${FILE_NAME}.h\" "
            "/dlldata \"${CMAKE_CURRENT_BINARY_DIR}/${FILE_NAME}_dlldata.c\" "
            "/iid \"${CMAKE_CURRENT_BINARY_DIR}/${FILE_NAME}_i.c\" "
            "/proxy \"${CMAKE_CURRENT_BINARY_DIR}/${FILE_NAME}_p.c\" "
            "\"${FILE}\"\n"
        )
    endforeach()

    # Create the batch file with the midl commands to run
    file(WRITE ${MIDL_BATCH_FILE} ${MIDL_BATCH_FILE_CONTENT})

    # Ensure that the bin directory for the compiler is in PATH
    set(ENV_PATH $ENV{PATH})
    get_filename_component(CL_DIR_PATH ${CMAKE_CXX_COMPILER} DIRECTORY)
    list(APPEND ENV_PATH ${CL_DIR_PATH})
    set(ENV{PATH} "${ENV_PATH}")

    # Run the batch file to generate the RPC client stubs
    set(${GENERATED_CLIENT_STUBS} "GENERATED_CLIENT_STUBS_FOR_${MIDL_TARGET}")
    if(NOT DEFINED ${GENERATED_CLIENT_STUBS})
        execute_process(
            COMMAND "${MIDL_BATCH_FILE}"
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            # Redirect the output and error to suppress them
            OUTPUT_VARIABLE COMMAND_OUTPUT
            ERROR_VARIABLE COMMAND_ERROR
        )
        # Overwrite the generated ms-dtyp.h file to prevent error due to the redefinition of Windows base types
        configure_file(${CMAKE_CURRENT_FUNCTION_LIST_DIR}/ms-dtyp.h.in ${CMAKE_CURRENT_BINARY_DIR}/ms-dtyp.h)
        set(${GENERATED_CLIENT_STUBS} TRUE CACHE BOOL "Has midl been ran to generate the client stubs?" FORCE)
    endif()

    # Populate the MIDL_OUTPUT_FILES variable, skipping _c.c files that were not generated
    foreach(FILE IN ITEMS ${IDL_FILES})
        list(APPEND MIDL_OUTPUT_FILES ${CMAKE_CURRENT_BINARY_DIR}/${FILE_NAME}.h)
        if(EXISTS ${CMAKE_CURRENT_BINARY_DIR}/${FILE_NAME}.c)
            list(APPEND MIDL_OUTPUT_FILES ${CMAKE_CURRENT_BINARY_DIR}/${FILE_NAME}.c)
        endif()
        if(EXISTS ${CMAKE_CURRENT_BINARY_DIR}/${FILE_NAME}_i.c)
            list(APPEND MIDL_OUTPUT_FILES ${CMAKE_CURRENT_BINARY_DIR}/${FILE_NAME}_i.c)
        endif()
    endforeach()

    # Add the output files to the target
    target_sources(${MIDL_TARGET} PRIVATE ${MIDL_OUTPUT_FILES})
    target_include_directories(${MIDL_TARGET} PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR} # For normal headers
        ${CMAKE_CURRENT_BINARY_DIR} # For MIDL outputed headers
    )
endfunction()