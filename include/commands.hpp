#pragma once
#include <cloudap.hpp>
#include <cxxopts.hpp>
#include <kerberos.hpp>
#include <msv1_0.hpp>
#include <negotiate.hpp>
#include <pku2u.hpp>
#include <schannel.hpp>
#include <wdigest.hpp>

namespace Cloudap {
    bool Call(const std::shared_ptr<Lsa>& lsa, const std::vector<char*>& args);
}

namespace Kerberos {
    bool Call(const std::shared_ptr<Lsa>& lsa, const std::vector<char*>& args);
}

namespace Msv1_0 {
    bool Call(const std::shared_ptr<Lsa>& lsa, const std::vector<char*>& args);
}

namespace Negotiate {
    bool Call(const std::shared_ptr<Lsa>& lsa, const std::vector<char*>& args);
}

namespace Pku2u {
    bool Call(const std::shared_ptr<Lsa>& lsa, const std::vector<char*>& args);
}

namespace Schannel {
    bool Call(const std::shared_ptr<Lsa>& proxy, const std::vector<char*>& args);
}

namespace Spm {
    bool Call(const std::shared_ptr<Lsa>& lsa, const std::vector<char*>& args);
}

namespace Wdigest {
    bool Call(const std::shared_ptr<Lsa>& proxy, const std::vector<char*>& args);
}