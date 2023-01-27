#pragma once
#include <rpc.h>
#include <string>

// We include rpcndr.h for the error_status_t typedef, but that will add annotations to the midl_user_* functions
// with Microsoft's source-code annotation language (SAL). We could modify the function signatures to match these
// annotations but there is no guarantee they will be consistent across SDK functions. So instead we will disable
// the two warnings regarding the mismatch in function annotations to prevent the VS projects with default settings
// from yelling at us.
#include <rpcndr.h>
#pragma warning(disable : 28251)
#pragma warning(disable : 28252)

extern "C" {
    void* __RPC_USER midl_user_allocate(_In_ size_t size);
    void __RPC_USER midl_user_free(void* pBuffer);
}

namespace Rpc {
    class Client {
    public:
        Client(RPC_WSTR alpcPort);
        Client(const std::wstring& server, RPC_WSTR protoSeq, RPC_WSTR endpoint, RPC_WSTR uuid = nullptr);
        ~Client();

        bool Bind(RPC_BINDING_HANDLE* binding);
        template<class Func, class... Args>
        error_status_t Call(Func function, Args... arguments) const {
            RpcTryExcept
                return function(arguments...);
            RpcExcept(EXCEPTION_EXECUTE_HANDLER)
                std::wcerr << L"Exception during RPC function call for binding: " << reinterpret_cast<LPWSTR>(this->stringBinding) << std::endl;
                std::wcerr << GetExceptionCode() << std::endl;
                return GetExceptionCode();
            RpcEndExcept
        }
        auto IsBound() const { return bound; }
        auto RpcString() const { return stringBinding; }

    private:
        RPC_BINDING_HANDLE* binding{ nullptr };
        bool bound{ false };
        RPC_WSTR endpoint;
        RPC_WSTR protoSeq;
        std::wstring server;
        RPC_WSTR stringBinding{ nullptr };
        RPC_WSTR uuid;
    };

    RPC_WSTR String(const UUID& uuid);
}