#include "Hashes.h"

namespace OpenPGP {
namespace Hash {

std::string use(const uint8_t alg, const std::string & data){
    switch (alg){
        // case 0: // don't hash; not defined in standard
            // return data;
        case ID::MD5:
            return MD5(data).digest();
            break;
        case ID::SHA1:
            return SHA1(data).digest();
            break;
        case ID::RIPEMD160:
            return RIPEMD160(data).digest();
            break;
        case ID::SHA256:
            return SHA256(data).digest();
            break;
        case ID::SHA384:
            return SHA384(data).digest();
            break;
        case ID::SHA512:
            return SHA512(data).digest();
            break;
        case ID::SHA224:
            return SHA224(data).digest();
            break;
        default:
            throw std::runtime_error("Error: Hash value not defined or reserved.");
            break;
    }
}

}
}