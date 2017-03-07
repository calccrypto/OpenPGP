#include "Hashes.h"

std::string use_hash(const uint8_t alg, const std::string & data){
    switch (alg){
        // case 0: // don't hash; not defined in standard
            // return data;
        case Hash::MD5:
            return MD5(data).digest();
            break;
        case Hash::SHA1:
            return SHA1(data).digest();
            break;
        case Hash::RIPEMD160:
            return RIPEMD160(data).digest();
            break;
        case Hash::SHA256:
            return SHA256(data).digest();
            break;
        case Hash::SHA384:
            return SHA384(data).digest();
            break;
        case Hash::SHA512:
            return SHA512(data).digest();
            break;
        case Hash::SHA224:
            return SHA224(data).digest();
            break;
        default:
            throw std::runtime_error("Error: Hash value not defined or reserved.");
            break;
    }
}