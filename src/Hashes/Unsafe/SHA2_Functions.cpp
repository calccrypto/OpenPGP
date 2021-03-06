#include "Hashes/Unsafe/SHA2_Functions.h"

namespace OpenPGP {
namespace Hash {

uint64_t Ch(const uint64_t &  m, const uint64_t & n, const uint64_t & o) {
    return (m & n) ^ (~m & o);
}

uint64_t  Maj(const uint64_t & m, const uint64_t & n, const uint64_t & o) {
    return (m & n) ^ (m & o) ^ (n & o);
}

}
}