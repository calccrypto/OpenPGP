#include "Hashes/OpenSSL/SHA224.h"

namespace OpenPGP {
namespace Hash {

SHA224::SHA224() :
    MerkleDamgard(),
    ctx()
{
    SHA224_Init(&ctx);
}

SHA224::SHA224(const std::string & str) :
    SHA224()
{
    update(str);
}

void SHA224::update(const std::string & str) {
    SHA224_Update(&ctx, str.c_str(), str.size());
}

std::string SHA224::hexdigest() {
    unsigned char buf[SHA224_DIGEST_LENGTH];
    SHA224_Final(buf, &ctx);
    return hexlify(std::string((char *) buf, SHA224_DIGEST_LENGTH));
}

std::size_t SHA224::blocksize() const {
    return 512;
}

std::size_t SHA224::digestsize() const {
    return 224;
}

}
}