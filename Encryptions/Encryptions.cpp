#include "Encryptions.h"

namespace OpenPGP {
namespace Sym {

SymAlg::Ptr setup(const uint8_t sym_alg, const std::string & key){
    SymAlg::Ptr alg;
    switch(sym_alg){
        case Sym::ID::IDEA:
            alg = std::make_shared <IDEA> (key);
            break;
        case Sym::ID::TRIPLEDES:
            alg = std::make_shared <TDES> (key.substr(0, 8), TDES_mode1, key.substr(8, 8), TDES_mode2, key.substr(16, 8), TDES_mode3);
            break;
        case Sym::ID::CAST5:
            alg = std::make_shared <CAST128> (key);
            break;
        case Sym::ID::BLOWFISH:
            alg = std::make_shared <Blowfish> (key);
            break;
        case Sym::ID::AES128:
        case Sym::ID::AES192:
        case Sym::ID::AES256:
            alg = std::make_shared <AES> (key);
            break;
        case Sym::ID::TWOFISH256:
            alg = std::make_shared <Twofish> (key);
            break;
        case Sym::ID::CAMELLIA128:
        case Sym::ID::CAMELLIA192:
        case Sym::ID::CAMELLIA256:
            alg = std::make_shared <Camellia> (key);
            break;
        default:
            throw std::runtime_error("Error: Unknown Symmetric Key Algorithm value.");
            break;
    }
    return alg;
}

}
}