target_sources(sspi PRIVATE
    crypt.cpp
    lsa.cpp
    msv1_0.cpp
    pku2u.cpp
    schannel.cpp
    wdigest.cpp
)
target_link_libraries(sspi PUBLIC Bcrypt.lib Crypt32.lib Ntdll.lib Rpcrt4.dll Secur32.lib)
target_idl_sources(sspi CLIENT SOURCES ms-sspir.idl)
