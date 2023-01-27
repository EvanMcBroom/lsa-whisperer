#include <iostream>
#include <rpc.hpp>
#include <vector>

extern "C" {
    void __RPC_FAR* __RPC_USER midl_user_allocate(size_t cBytes) {
        return malloc(cBytes);
    }

    void __RPC_USER midl_user_free(void* pBuffer) {
        free(pBuffer);
    }
}

namespace Rpc {
    Client::Client(RPC_WSTR alpcPort)
        : protoSeq(reinterpret_cast<RPC_WSTR>(L"ncalrpc")), server(), endpoint(alpcPort), uuid(nullptr) {
    }

    Client::Client(const std::wstring& server, RPC_WSTR protoSeq, RPC_WSTR endpoint, RPC_WSTR uuid)
        : protoSeq(protoSeq), server(server), endpoint(endpoint), uuid(uuid) {
    }

    Client::~Client() {
        RpcStringFreeW(&this->stringBinding);
        if (bound) {
            RpcBindingFree(this->binding);
        }
    }

    bool Client::Bind(RPC_BINDING_HANDLE* binding) {
        RpcTryExcept
            auto address{ (server.length()) ? reinterpret_cast<RPC_WSTR>(server.data()) : nullptr };
            if (RpcStringBindingComposeW(this->uuid, this->protoSeq, address, endpoint, nullptr, &this->stringBinding) == RPC_S_OK) {
                if (RpcBindingFromStringBindingW(this->stringBinding, binding) == RPC_S_OK) {
                    this->binding = binding;
                    bound = true;
                }
            }
            else {
                std::wcerr << L"Error composing string for RPC binding: " << server << std::endl;
            }
        RpcExcept(EXCEPTION_EXECUTE_HANDLER)
            std::wcerr << L"Could not connect to: " << reinterpret_cast<LPWSTR>(this->stringBinding);
        RpcEndExcept
            return bound;
    }

    RPC_WSTR String(const UUID& uuid) {
        RPC_WSTR rpcString;
        return (UuidToStringW(&uuid, &rpcString) == RPC_S_OK) ? rpcString : nullptr;
    }
}