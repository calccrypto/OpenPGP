#include "Hashes.h"

std::string use_hash(uint8_t flag, const std::string & data){
    switch (flag){
        case 0: // don't hash; not defined in standard
            return data;
        case 1:
            return MD5(data).digest();
            break;
        case 2:
            return SHA1(data).digest();
            break;
        case 3:
            return RIPEMD160(data).digest();
            break;
        case 8:
            return SHA256(data).digest();
            break;
        case 9:
            return SHA384(data).digest();
            break;
        case 10:
            return SHA512(data).digest();
            break;
        case 11:
            return SHA224(data).digest();
            break;
        default:
            throw std::runtime_error("Error: Hash value not defined or reserved.");
            break;
    }
}

