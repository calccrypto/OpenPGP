#include "RNG/RAND_bytes.h"

#include <cstdlib>
#include <stdexcept>

#include "common/includes.h"

namespace OpenPGP {
namespace RNG {

bool RAND_bytes::seeded = false;

void RAND_bytes::seed(const void * buf, int num) {
    if (!seeded) {
        ::RAND_seed(buf, num);
        seeded = true;
    }
}

RAND_bytes::RAND_bytes(...) {
    static const int num = 1024;
    void * buf = malloc(num);
    seed(buf, num);
    free(buf);
}

RAND_bytes::RAND_bytes(const std::string & seed)
    : RAND_bytes(seed.c_str(), seed.size())
{}

RAND_bytes::RAND_bytes(const void * buf, int num) {
    seed(buf, num);
}

std::string RAND_bytes::rand_bits(const unsigned int & bits, const std::size_t max_attempts) {
    return binify(rand_bytes((bits >> 3) + (bool) (bits & 0xff), max_attempts)).substr(0, bits);
}

std::string RAND_bytes::rand_bytes(const unsigned int & bytes, const std::size_t max_attempts) {
    RAND_bytes();

    unsigned char * buf = new unsigned char[bytes];

    std::size_t attempt = 0;
    while ((attempt < max_attempts) && (::RAND_bytes(buf, bytes) != 1)) {
        attempt++;
    }

    if (attempt == max_attempts) {
        throw std::runtime_error("Could not get " + std::to_string(bytes) + " random bytes after " + std::to_string(max_attempts) + " attempts");
    }

    const std::string ret((char *) buf, bytes);
    delete [] buf;
    return ret;
}

}
}
