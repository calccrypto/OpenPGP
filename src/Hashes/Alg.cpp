#include "Hashes/Alg.h"

namespace OpenPGP {
namespace Hash {

Alg::Alg() {}

Alg::~Alg() {}

std::string Alg::digest() {
    return unhexlify(hexdigest());
}

}
}