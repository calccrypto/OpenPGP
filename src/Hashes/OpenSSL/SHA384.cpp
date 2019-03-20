#include "Hashes/OpenSSL/SHA384.h"

namespace OpenPGP {
namespace Hash {

SHA384::SHA384() :
    MerkleDamgard(),
    ctx()
{
    SHA384_Init(&ctx);
}

SHA384::SHA384(const std::string & str) :
    SHA384()
{
    update(str);
}

void SHA384::update(const std::string & str) {
    SHA384_Update(&ctx, str.c_str(), str.size());
}

std::string SHA384::hexdigest() {
    unsigned char buf[SHA384_DIGEST_LENGTH];
    SHA384_Final(buf, &ctx);
    return hexlify(std::string((char *) buf, SHA384_DIGEST_LENGTH));
}

std::size_t SHA384::blocksize() const {
    return 1024;
}

std::size_t SHA384::digestsize() const {
    return 384;
}

}
}