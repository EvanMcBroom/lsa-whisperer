#pragma once
#include <pch.hpp>

#include <lsa.hpp>

#define LIVE_NAME_A "LiveSSP"

namespace Live {
    enum class PROTOCOL_MESSAGE_TYPE : ULONG {
        RenameAccount,
        TransferCredential,
        GetSignedProofOfPossessionToken,
        SetUnsignedProofOfPossessionToken,
        DeleteProofOfPossessionToken
    };

    class Proxy {
    public:
        Proxy(const std::shared_ptr<Lsa>& lsa);

        bool GetSignedProofOfPossessionToken() const;

        std::shared_ptr<Lsa> lsa;

    private:
        // You must free all returnBuffer outputs with LsaFreeReturnBuffer
        bool CallPackage(PROTOCOL_MESSAGE_TYPE MessageType) const;

        template<typename _Request, typename _Response>
        bool CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const;
    };
}