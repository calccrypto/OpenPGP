#include "Hashes/Hashes.h"

namespace OpenPGP {
namespace Hash {

std::string use(const uint8_t alg, const std::string & data) {
    return get_instance(alg, data) -> digest();
}

Instance get_instance(const uint8_t alg, const std::string & data) {
    Instance ptr = nullptr;
    switch (alg) {
        case ID::MD5:
            ptr = std::make_shared <MD5> (data);
            break;
        case ID::SHA1:
            ptr = std::make_shared <SHA1> (data);
            break;
        case ID::RIPEMD160:
            ptr = std::make_shared <RIPEMD160> (data);
            break;
        case ID::SHA256:
            ptr = std::make_shared <SHA256> (data);
            break;
        case ID::SHA384:
            ptr = std::make_shared <SHA384> (data);
            break;
        case ID::SHA512:
            ptr = std::make_shared <SHA512> (data);
            break;
        case ID::SHA224:
            ptr = std::make_shared <SHA224> (data);
            break;
        default:
            throw std::runtime_error("Error: Hash value not defined or reserved.");
            break;
    }

    return ptr;
}

}
}
