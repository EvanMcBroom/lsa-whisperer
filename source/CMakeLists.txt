target_sources(${PROJECT_NAME} PRIVATE
    crypt.cpp
    lsa.cpp
)
target_link_libraries(${PROJECT_NAME} PUBLIC Bcrypt.lib Crypt32.lib)

target_ap_sources(msv1_0 SOURCES
    msv1_0/args.cpp
    msv1_0/cache.cpp
    msv1_0/stubs.cpp
)

target_ap_sources(pku2u SOURCES
    pku2u/args.cpp
    pku2u/stubs.cpp
)

target_ap_sources(schannel SOURCES
    schannel/args.cpp
    schannel/stubs.cpp
)