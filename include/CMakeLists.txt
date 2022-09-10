target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_sources(${PROJECT_NAME} PRIVATE
    crypt.hpp
    lsa.hpp
    netlogon.hpp
)
target_precompile_headers(${PROJECT_NAME} PRIVATE <windows.h>)

target_include_directories(msv1_0 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_sources(msv1_0 PRIVATE
    msv1_0/args.hpp
    msv1_0/cache.hpp
    msv1_0/messages.hpp
    msv1_0/stubs.hpp
)
target_precompile_headers(msv1_0 PRIVATE <windows.h>)

target_include_directories(pku2u PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_sources(pku2u PRIVATE
    pku2u/args.hpp
    pku2u/messages.hpp
    pku2u/stubs.hpp
)
target_precompile_headers(pku2u PRIVATE <windows.h>)

target_include_directories(schannel PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_sources(schannel PRIVATE
    schannel/args.hpp
    schannel/messages.hpp
    schannel/stubs.hpp
)
target_precompile_headers(schannel PRIVATE <windows.h>)