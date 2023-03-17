#pragma once
#include <Winternl.h>
#include <cxxopts.hpp>
#include <lsa.hpp>

namespace Negotiate {
    constexpr auto MaxPrefix() {
        return 32;
    }

    enum class PROTOCOL_MESSAGE_TYPE : ULONG {
        EnumPackagePrefixes,
        GetCallerName,
        TransferCred,
        EnumPackageNames
    };

    typedef struct _PACKAGE_PREFIX {
        ULONG_PTR PackageId;
        PVOID PackageDataA; // Unused, set to nullptr by negotiate
        PVOID PackageDataW; // Unused, set to nullptr by negotiate
        ULONG_PTR PrefixLen;
        UCHAR Prefix[MaxPrefix()];
    } PACKAGE_PREFIX, *PPACKAGE_PREFIX;

    typedef struct _PACKAGE_PREFIXES {
        ULONG MessageType;
        ULONG PrefixCount;
        ULONG Offset; // Offset to array of PACKAGE_PREFIX
        ULONG Pad;
    } PACKAGE_PREFIXES, *PPACKAGE_PREFIXES;

    typedef struct _CALLER_NAME_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::GetCallerName };
        LUID LogonId;
    } CALLER_NAME_REQUEST, *PCALLER_NAME_REQUEST;

    typedef struct _CALLER_NAME_RESPONSE {
        PROTOCOL_MESSAGE_TYPE MessageType;
        PWSTR CallerName;
    } CALLER_NAME_RESPONSE, *PCALLER_NAME_RESPONSE;

    class Proxy {
    public:
        Proxy(const std::shared_ptr<Lsa>& lsa);

        // A subset of the supported functions in negotiate
        bool EnumPackagePrefixes() const;
        bool GetCallerName(PLUID logonId) const;
        bool EnumPackageNames() const;

    protected:
        std::shared_ptr<Lsa> lsa;

    private:
        // You must free all returnBuffer outputs with LsaFreeReturnBuffer
        template<typename _Request, typename _Response>
        bool CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const;
    };

    bool HandleFunction(std::ostream& out, const Proxy& proxy, const std::string& function, const cxxopts::ParseResult& options);
    void Parse(std::ostream& out, const std::vector<std::string>& args);
}