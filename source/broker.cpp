#include <Windows.h>
#include <iostream>
#include <lsa.hpp>
#include <ms-sspir_c.h>
#include <ms-sspir_s.h>

#pragma comment(lib, "Rpcrt4.lib")

int wmain(int argc, wchar_t** argv) {
    if (argc > 1) {
        // Process the user arguments
        auto alpcPort{ const_cast<wchar_t*>((argc > 2) ? argv[1] : L"lsasspirpc") };
        std::wstring eventName{ (argc > 2) ? argv[1] : argv[1] };
        // Bind to the implicit handle for the actual SSPI RPC server
        Rpc::Client rpcClient(reinterpret_cast<RPC_WSTR>(L"lsasspirpc"));
        if (rpcClient.Bind(&SspiRpcImplicitHandle)) {
            // Setup and start the SSPI broker RPC server
            auto protoSeq{ reinterpret_cast<RPC_WSTR>(L"ncalrpc") };
            RPC_WSTR endpoint{ reinterpret_cast<RPC_WSTR>(L"sspibroker") };
            if (RpcServerUseProtseqEpW(protoSeq, RPC_C_PROTSEQ_MAX_REQS_DEFAULT, endpoint, nullptr) == RPC_S_OK) {
                if (RpcServerRegisterIf2(sspirpc_v1_0_s_ifspec, nullptr, nullptr, RPC_IF_ALLOW_LOCAL_ONLY, RPC_C_LISTEN_MAX_CALLS_DEFAULT, -1, nullptr) == RPC_S_OK) {
                    if (RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, false) == RPC_S_OK) {
                        // Listen until another process signals the designated event name
                        auto event{ CreateEventW(nullptr, true, false, argv[1]) };
                        if (event) {
                            WaitForSingleObject(event, INFINITE);
                            // Then stop and teardown the server
                            if (RpcMgmtStopServerListening(nullptr) == RPC_S_OK) {
                                if (RpcServerUnregisterIf(nullptr, nullptr, false) == RPC_S_OK) {
                                    return 0;
                                }
                            }
                        }
                    }
                }
            }
        }
    } else {
        std::wcout << argv[0] << L" [alpc port name] {event name}" << std::endl;
    }
    return 1;
}