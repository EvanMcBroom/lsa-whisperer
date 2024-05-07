# Absolute paths are used to allow the USE_STAMP_FILE option to be used with doxygen_add_docs
set(SSPI_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/all.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/cloudap.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/crypt.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/live.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/lsa.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/msv1_0.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/negoexts.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/negotiate.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/pku2u.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/rpc.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/schannel.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/spm.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/wdigest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/kerberos.cpp

)
set(SSPI_SOURCES ${SSPI_SOURCES} PARENT_SCOPE)
target_sources(sspi PRIVATE ${SSPI_SOURCES})
target_link_libraries(sspi PUBLIC Bcrypt.lib Crypt32.lib Ntdll.lib Rpcrt4.dll Secur32.lib)
target_idl_sources(sspi CLIENT SOURCES ms-sspir.idl)

target_sources(lsa-whisperer PRIVATE
    cli.cpp
    commands.cpp
    main.cpp
    token.cpp
)