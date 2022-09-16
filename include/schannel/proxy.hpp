#pragma once
#include <lsa.hpp>

namespace Schannel {
    class Proxy : public SspiProxy {
    public:
        // A subset of the supported functions in pku2u
        bool CacheInfo(PLUID logonId, const std::wstring& serverName, ULONG flags) const;
        bool LookupCert(const std::vector<byte>& certificate, ULONG flags, std::vector<std::vector<byte>> issuers) const;
        bool LookupExternalCert(ULONG type, const std::vector<byte>& credential, ULONG flags) const;
        bool PerfmonInfo(ULONG flags) const;
        bool PurgeCache(PLUID logonId, const std::wstring& serverName, ULONG flags) const;
        bool StreamSizes() const;

    private:
        // You must free all returnBuffer outputs with LsaFreeReturnBuffer
        template<typename _Request, typename _Response>
        bool CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const;
    };
}