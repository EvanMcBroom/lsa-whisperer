#pragma once
#include <pch.hpp>

#include <lsa.hpp>

#define NEGOEX_NAME_A "NegoExtender"

namespace Negoexts {
    enum class PROTOCOL_MESSAGE_TYPE : ULONG {
        GetCredUIContext = 0x1,
        UpdateCredentials,
        LookupContext,
        FlushContext,
    };

    extern const GUID SEC_WINNT_AUTH_DATA_TYPE_CERT;
    extern const GUID SEC_WINNT_AUTH_DATA_TYPE_CSP_DATA;
    extern const GUID SEC_WINNT_AUTH_DATA_TYPE_PASSWORD;

    typedef struct _FLUSH_CONTEXT_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::FlushContext };
        USHORT MessageSize = sizeof(struct _FLUSH_CONTEXT_REQUEST);
        LPVOID ContextHandle;
    } FLUSH_CONTEXT_REQUEST, *PFLUSH_CONTEXT_REQUEST;

    typedef struct _GET_CRED_UI_CONTEXT_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::GetCredUIContext };
        USHORT MessageSize = sizeof(struct _GET_CRED_UI_CONTEXT_REQUEST);
        LPVOID ContextHandle;
        GUID CredType; // As specified by the SEC_WINNT_AUTH_DATA_TYPE_* macros
        LUID LogonSession;
    } GET_CRED_UI_CONTEXT_REQUEST, *PGET_CRED_UI_CONTEXT_REQUEST;

    typedef struct _GET_CRED_UI_CONTEXT_RESPONSE {
        PROTOCOL_MESSAGE_TYPE MessageType;
        USHORT MessageSize;
        // FlatCredUIContext
    } GET_CRED_UI_CONTEXT_RESPONSE, *PGET_CRED_UI_CONTEXT_RESPONSE;

    typedef struct _LOOKUP_CONTEXT_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::LookupContext };
        USHORT MessageSize = sizeof(struct _LOOKUP_CONTEXT_REQUEST);
        ULONG TargetOffset;
        USHORT TargetLength;
    } LOOKUP_CONTEXT_REQUEST, *PLOOKUP_CONTEXT_REQUEST;

    typedef struct _LOOKUP_CONTEXT_RESPONSE {
        PROTOCOL_MESSAGE_TYPE MessageType;
        USHORT MessageSize;
        LPVOID ContextHandle;
    } LOOKUP_CONTEXT_RESPONSE, *PLOOKUP_CONTEXT_RESPONSE;

    typedef struct _UPDATE_CREDENTIALS_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::UpdateCredentials };
        USHORT MessageSize = sizeof(struct _UPDATE_CREDENTIALS_REQUEST);
        LPVOID ContextHandle;
        GUID CredType; // As specified by the SEC_WINNT_AUTH_DATA_TYPE_* macros
        ULONG FlatCredUIContextOffset;
        ULONG FlatCredUIContextLength;
    } UPDATE_CREDENTIALS_REQUEST, *PUPDATE_CREDENTIALS_REQUEST;

    class Proxy {
    public:
        Proxy(const std::shared_ptr<Lsa>& lsa);
        
        bool FlushContext(LPVOID contextHandle) const;
        bool GetCredUIContext(LPVOID contextHandle, GUID& credType, LUID& logonSession) const;
        bool LookupContext(const std::wstring& target) const;
        bool UpdateCredentials(LPVOID contextHandle, GUID& credType, const std::string& data) const;

    protected:
        std::shared_ptr<Lsa> lsa;

    private:
        // You must free all returnBuffer outputs with LsaFreeReturnBuffer
        bool CallPackage(const std::string& submitBuffer, void** returnBuffer) const;

        template<typename _Request, typename _Response>
        bool CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const;
    };
}