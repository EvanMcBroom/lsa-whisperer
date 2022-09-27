target_sources(core PRIVATE
    crypt.cpp
    lsa.cpp
)
target_link_libraries(core PUBLIC Bcrypt.lib Crypt32.lib Ntdll.lib Secur32.lib)

target_sources(msv1_0 PRIVATE
    msv1_0/args.cpp
    msv1_0/cache.cpp
    msv1_0/proxy.cpp
)

target_sources(pku2u PRIVATE
    pku2u/args.cpp
    pku2u/proxy.cpp
)

target_sources(schannel PRIVATE
    schannel/args.cpp
    schannel/proxy.cpp
)

#target_sources(lsa-whisperer PRIVATE
#    cli.cpp
#)