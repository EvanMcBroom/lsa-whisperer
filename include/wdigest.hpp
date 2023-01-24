#pragma once
#include <Windows.h>
#include <Winternl.h>
#include <cxxopts.hpp>
#include <lsa.hpp>

namespace Wdigest {
    enum class PROTOCOL_MESSAGE_TYPE : ULONG {
        VerifyDigest = 0x1a,
        VerifyDigestResponse = 0x0a,
    };
    
    enum class Flags : USHORT {
        CracknameOnDc = 0x01, // The username and realm needs to be cracked
        AuthzidProvided = 0x02,
        ServersDomain = 0x04, // Indicate that this is the Server's DC to have it expand group membership
        NobsDecode = 0x08, // Wire communication is done without backslash encoding if set
        BsEncodeClientBroken = 0x10, // Set if backslash encoding is possibly boken on client
        QouteQop = 0x20 // set according to the context if quote the QOP - client side only
    };

    // Originally called _DIGEST_BLOB_REQUEST
    typedef struct _VERIFY_DIGEST_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::VerifyDigest };
        USHORT version;
        USHORT cbBlobSize;
        USHORT digest_type;
        USHORT qop_type;
        USHORT alg_type;
        USHORT charset_type;
        USHORT cbCharValues;
        USHORT name_format;
        Flags usFlags;
        USHORT cbAccountName;
        USHORT cbCrackedDomain;
        USHORT cbWorkstation;
        USHORT ulReserved3;
        ULONG64 pad1;
        char cCharValues; // dummy char to mark start of field-values
    } VERIFY_DIGEST_REQUEST, *PVERIFY_DIGEST_REQUEST;

    // Originally called _DIGEST_BLOB_RESPONSE
    // Followed by the authentication data (a PAC) and a NetBIOS name
    typedef struct _VERIFY_DIGEST_RESPONSE {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::VerifyDigestResponse };
        USHORT version;
        NTSTATUS Status; // If the authentication was successfull
        USHORT SessionKeyMaxLength;
        ULONG ulAuthDataSize;
        USHORT usAcctNameSize; // Size of the NetBIOS name after AuthData
        USHORT ulReserved1;
        ULONG ulBlobSize; // Si
        ULONG ulReserved3;
        char SessionKey[32 + 1]; // MD5 asciihexdfs
        ULONG64 pad1;
        char cAuthData[1]; // PAC for the user
        // Place group info here for LogonUser
    } VERIFY_DIGEST_RESPONSE, *PVERIFY_DIGEST_RESPONSE;

    class Proxy : public Sspi {
    public:
        // A subset of the supported functions in pku2u
        bool VerifyDigest() const;

    private:
        // You must free all returnBuffer outputs with LsaFreeReturnBuffer
        template<typename _Request, typename _Response>
        bool CallPackagePassthrough(const _Request& submitBuffer, _Response** returnBuffer) const;
    };
    
	bool HandleFunction(std::ostream& out, const Proxy& proxy, const cxxopts::ParseResult& options);
	void Parse(std::ostream& out, const std::vector<std::string>& args);
}