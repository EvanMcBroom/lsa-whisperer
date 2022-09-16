target_include_directories(core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_sources(core PRIVATE
    crypt.hpp
    lsa.hpp
    netlogon.hpp
)
target_precompile_headers(core PUBLIC <windows.h>)

target_sources(msv1_0 PRIVATE
    msv1_0/args.hpp
    msv1_0/cache.hpp
    msv1_0/messages.hpp
    msv1_0/proxy.hpp
)

target_sources(pku2u PRIVATE
    pku2u/args.hpp
    pku2u/messages.hpp
    pku2u/proxy.hpp
)

target_sources(schannel PRIVATE
    schannel/args.hpp
    schannel/messages.hpp
    schannel/proxy.hpp
)

target_sources(lsa-whisperer PRIVATE
    lsa-whisperer.hpp
)