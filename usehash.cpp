#include "usehash.h"

std::string use_hash(uint8_t flag, std::string data){
    switch (flag){
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
            std::cerr << "Error: Hash value not defined or reserved" << std::endl;
            exit(1);
            break;
    }
}

