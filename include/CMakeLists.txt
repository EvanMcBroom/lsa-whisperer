target_include_directories(msv1_0-cli PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_sources(msv1_0-cli PRIVATE
    cache.hpp
    crypt.hpp
    messages.hpp
    msv1_0.hpp
    netlogon.hpp
)
target_precompile_headers(msv1_0-cli PRIVATE <windows.h>)