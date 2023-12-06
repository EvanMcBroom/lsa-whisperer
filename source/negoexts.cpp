#define _NTDEF_ // Required to include both Ntsecapi and Winternl
#include <Winternl.h>
#include <crypt.hpp>
#include <lsa.hpp>
#include <msv1_0.hpp>
#include <negoexts.hpp>
#include <security.h>
#include <string>

namespace Negoexts {
    const GUID SEC_WINNT_AUTH_DATA_TYPE_CERT = { 0x235f69ad, 0x73fb, 0x4dbc, { 0x82, 0x3, 0x6, 0x29, 0xe7, 0x39, 0x33, 0x9b } };
    const GUID SEC_WINNT_AUTH_DATA_TYPE_CSP_DATA = { 0x68fd9879, 0x79c, 0x4dfe, { 0x82, 0x81, 0x57, 0x8a, 0xad, 0xc1, 0xc1, 0x0 } };
    const GUID SEC_WINNT_AUTH_DATA_TYPE_PASSWORD = { 0x28bfc32f, 0x10f6, 0x4738, { 0x98, 0xd1, 0x1a, 0xc0, 0x61, 0xdf, 0x71, 0x6a } };

    Proxy::Proxy(const std::shared_ptr<Lsa>& lsa)
        : lsa(lsa) {
    }

    bool Proxy::FlushContext(LPVOID contextHandle) const {
        FLUSH_CONTEXT_REQUEST request;
        request.ContextHandle = contextHandle;
        void* response;
        return CallPackage(request, &response);
    }

    bool Proxy::GetCredUIContext(LPVOID contextHandle, GUID& credType, LUID& logonSession) const {
        GET_CRED_UI_CONTEXT_REQUEST request;
        request.ContextHandle = contextHandle;
        request.CredType = credType;
        request.LogonSession.HighPart = logonSession.HighPart;
        request.LogonSession.LowPart = logonSession.LowPart;
        PGET_CRED_UI_CONTEXT_RESPONSE response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Proxy::LookupContext(const std::wstring& target) const {
        auto requestSize{ sizeof(LOOKUP_CONTEXT_REQUEST) + ((target.length() + 1) * sizeof(wchar_t)) };
        std::string requestBytes(requestSize, '\0');
        auto request{ reinterpret_cast<PLOOKUP_CONTEXT_REQUEST>(requestBytes.data()) };
        request->MessageType = PROTOCOL_MESSAGE_TYPE::LookupContext;
        request->MessageSize = requestSize;

        auto ptrTarget{ reinterpret_cast<std::byte*>(request + 1) };
        std::memcpy(ptrTarget, target.data(), target.size() * sizeof(wchar_t));
        request->TargetOffset = sizeof(LOOKUP_CONTEXT_REQUEST);
        request->TargetLength = target.size() * sizeof(wchar_t);

        PLOOKUP_CONTEXT_RESPONSE response;
        auto result{ this->CallPackage(requestBytes, reinterpret_cast<void**>(&response)) };
        if (result) {
            lsa->out << "ContextHandle: " << response->ContextHandle << std::endl;
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Proxy::UpdateCredentials(LPVOID contextHandle, GUID& credType, const std::string& data) const {
        auto requestSize{ sizeof(UPDATE_CREDENTIALS_REQUEST) + data.length() };
        std::string requestBytes(requestSize, '\0');
        auto request{ reinterpret_cast<PUPDATE_CREDENTIALS_REQUEST>(requestBytes.data()) };
        request->MessageType = PROTOCOL_MESSAGE_TYPE::UpdateCredentials;
        request->MessageSize = requestSize;

        request->ContextHandle = contextHandle;
        request->CredType = credType;

        auto ptrData{ reinterpret_cast<std::byte*>(request + 1) };
        std::memcpy(ptrData, data.data(), data.size());
        request->FlatCredUIContextOffset = sizeof(UPDATE_CREDENTIALS_REQUEST);
        request->FlatCredUIContextLength = data.length();

        void* response;
        return this->CallPackage(requestBytes, &response);
    }

    bool Proxy::CallPackage(const std::string& submitBuffer, void** returnBuffer) const {
        if (lsa->Connected()) {
            return lsa->CallPackage(NEGOEX_NAME_A, submitBuffer, returnBuffer);
        }
        return false;
    }

    template<typename _Request, typename _Response>
    bool Proxy::CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const {
        if (lsa->Connected()) {
            std::string stringSubmitBuffer(reinterpret_cast<const char*>(&submitBuffer), sizeof(decltype(submitBuffer)));
            return lsa->CallPackage(NEGOEX_NAME_A, stringSubmitBuffer, reinterpret_cast<void**>(returnBuffer));
        }
        return false;
    }
}