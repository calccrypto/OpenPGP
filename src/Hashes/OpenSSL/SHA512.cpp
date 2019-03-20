#include "Hashes/OpenSSL/SHA512.h"

namespace OpenPGP {
namespace Hash {

SHA512::SHA512() :
    MerkleDamgard(),
    ctx()
{
    SHA512_Init(&ctx);
}

SHA512::SHA512(const std::string & str) :
    SHA512()
{
    update(str);
}

void SHA512::update(const std::string & str) {
    SHA512_Update(&ctx, str.c_str(), str.size());
}

std::string SHA512::hexdigest() {
    unsigned char buf[SHA512_DIGEST_LENGTH];
    SHA512_Final(buf, &ctx);
    return hexlify(std::string((char *) buf, SHA512_DIGEST_LENGTH));
}

std::size_t SHA512::blocksize() const {
    return 1024;
}

std::size_t SHA512::digestsize() const {
    return 512;
}

}
}