#include "Hashes/OpenSSL/SHA1.h"

namespace OpenPGP {
namespace Hash {

SHA1::SHA1() :
    MerkleDamgard(),
    ctx()
{
    SHA1_Init(&ctx);
}

SHA1::SHA1(const std::string & str) :
    SHA1()
{
    update(str);
}

void SHA1::update(const std::string & str) {
    SHA1_Update(&ctx, str.c_str(), str.size());
}

std::string SHA1::hexdigest() {
    unsigned char buf[SHA_DIGEST_LENGTH];
    SHA1_Final(buf, &ctx);
    return hexlify(std::string((char *) buf, SHA_DIGEST_LENGTH));
}

std::size_t SHA1::blocksize() const {
    return 512;
}

std::size_t SHA1::digestsize() const {
    return 160;
}

}
}