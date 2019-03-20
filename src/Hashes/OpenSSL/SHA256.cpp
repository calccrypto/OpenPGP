#include "Hashes/OpenSSL/SHA256.h"

namespace OpenPGP {
namespace Hash {

SHA256::SHA256() :
    MerkleDamgard(),
    ctx()
{
    SHA256_Init(&ctx);
}

SHA256::SHA256(const std::string & str) :
    SHA256()
{
    update(str);
}

void SHA256::update(const std::string & str) {
    SHA256_Update(&ctx, str.c_str(), str.size());
}

std::string SHA256::hexdigest() {
    unsigned char buf[SHA256_DIGEST_LENGTH];
    SHA256_Final(buf, &ctx);
    return hexlify(std::string((char *) buf, SHA256_DIGEST_LENGTH));
}

std::size_t SHA256::blocksize() const {
    return 256;
}

std::size_t SHA256::digestsize() const {
    return 256;
}

}
}