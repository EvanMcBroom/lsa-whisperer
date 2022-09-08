#include <Windows.h>
#include <cache.hpp>
#include <msv1_0.hpp>
#include <pybind11/pybind11.h>

namespace {
    bool GetCredentialKey(size_t luid) {
        LUID tempLuid;
        reinterpret_cast<LARGE_INTEGER*>(&tempLuid)->QuadPart = luid;
        return MSV1_0::GetCredentialKey(&tempLuid);
    }
}

PYBIND11_MODULE(pymsv1_0, m) {
    m.doc() = "Python module for the MSV1_0 authentication package";
    m.attr("__version__") = MODULE_VERSION;
    m.def("get_credential_key", &GetCredentialKey, "");
}