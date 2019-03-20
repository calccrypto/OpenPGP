#include "Hashes/OpenSSL/RIPEMD160.h"

namespace OpenPGP {
namespace Hash {

RIPEMD160::RIPEMD160() :
    MerkleDamgard(),
    ctx()
{
    RIPEMD160_Init(&ctx);
}

RIPEMD160::RIPEMD160(const std::string & str) :
    RIPEMD160()
{
    update(str);
}

void RIPEMD160::update(const std::string & str) {
    RIPEMD160_Update(&ctx, str.c_str(), str.size());
}

std::string RIPEMD160::hexdigest() {
    unsigned char buf[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160_Final(buf, &ctx);
    return hexlify(std::string((char *) buf, RIPEMD160_DIGEST_LENGTH));
}

std::size_t RIPEMD160::blocksize() const {
    return 512;
}

std::size_t RIPEMD160::digestsize() const {
    return 160;
}

}
}