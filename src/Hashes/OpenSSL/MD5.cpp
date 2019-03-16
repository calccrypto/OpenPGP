#include "Hashes/OpenSSL/MD5.h"

namespace OpenPGP {
namespace Hash {

MD5::MD5() :
    MerkleDamgard(),
    ctx()
{
    MD5_Init(&ctx);
}

MD5::MD5(const std::string & str) :
    MD5()
{
    update(str);
}

void MD5::update(const std::string & str) {
    MD5_Update(&ctx, str.c_str(), str.size());
}

std::string MD5::hexdigest() {
    unsigned char buf[MD5_DIGEST_LENGTH];
    MD5_Final(buf, &ctx);
    return hexlify(std::string((char *) buf, MD5_DIGEST_LENGTH));
}

std::size_t MD5::blocksize() const {
    return 512;
}

std::size_t MD5::digestsize() const {
    return 128;
}

}
}