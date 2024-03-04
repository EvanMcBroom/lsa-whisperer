#include <cstring>
#include <spm.hpp>

namespace AuApi {
    _MESSAGE::_MESSAGE(AuApi::NUMBER api) {
        std::memset(this, '\0', sizeof(_MESSAGE));
        pmMessage.u1.s1.DataLength = sizeof(_MESSAGE) - sizeof(PORT_MESSAGE);
        pmMessage.u1.s1.TotalLength = sizeof(_MESSAGE);
        ApiNumber = api;
    }
}

namespace SpmApi {
    _MESSAGE::_MESSAGE(SpmApi::NUMBER api, size_t argSize, unsigned short flags, void* context, bool kernelMode) {
        std::memset(this, '\0', sizeof(_MESSAGE));
        pmMessage.u1.s1.DataLength = SecBaseMessageSize(argSize);
        pmMessage.u1.s1.TotalLength = pmMessage.u1.s1.DataLength + sizeof(PORT_MESSAGE);
        ApiCallRequest.dwAPI = api;
        ApiCallRequest.Args.SpmArguments.fAPI = flags;
        ApiCallRequest.Args.SpmArguments.ContextPointer = context;
        pmMessage.u2.s2.Type |= (kernelMode) ? LPC_KERNELMODE_MESSAGE : 0;
    }
}