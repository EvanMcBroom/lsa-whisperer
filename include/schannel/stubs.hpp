#pragma once
#include <lsa.hpp>
#include <string>
#include <vector>

namespace Schannel {
    template<typename _Request, typename _Response>
    bool CallPackage(const _Request& submitBuffer, _Response** returnBuffer);

    bool CacheInfo(PLUID logonId, const std::wstring& serverName, ULONG flags);
    bool LookupCert(const std::vector<byte>& certificate, ULONG flags, std::vector<std::vector<byte>> issuers);
    bool LookupExternalCert(ULONG type, const std::vector<byte>& credential, ULONG flags);
    bool PerfmonInfo(ULONG flags);
    bool PurgeCache(PLUID logonId, const std::wstring& serverName, ULONG flags);
    bool StreamSizes();
}