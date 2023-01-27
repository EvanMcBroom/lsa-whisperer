target_include_directories(sspi PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/nt
)
target_sources(sspi PRIVATE
    crypt.hpp
    lsa.hpp
    msv1_0.hpp
    netlogon.hpp
    pku2u.hpp
    rpc.hpp
    schannel.hpp
    spm.hpp
    wdigest.hpp
)
target_precompile_headers(sspi PUBLIC <windows.h>)

target_sources(lsa-whisperer PRIVATE
    cli.hpp
)