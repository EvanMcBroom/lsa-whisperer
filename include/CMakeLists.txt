target_include_directories(sspi PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
# Absolute paths are used to allow the USE_STAMP_FILE option to be used with doxygen_add_docs
set(SSPI_HEADERS
    ${CMAKE_CURRENT_SOURCE_DIR}/all.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/cloudap.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/crypt.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/live.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/lsa.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/msv1_0.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/negoexts.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/negotiate.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/pch.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/pku2u.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/rpc.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/schannel.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/spm.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/wdigest.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/kerberos.hpp

)
set(SSPI_HEADERS ${SSPI_HEADERS} PARENT_SCOPE)
target_sources(sspi PRIVATE ${SSPI_HEADERS})
target_precompile_headers(sspi PUBLIC <pch.hpp>)

target_sources(lsa-whisperer PRIVATE
    cli.hpp
    commands.hpp
    lazy.hpp
    token.hpp
)