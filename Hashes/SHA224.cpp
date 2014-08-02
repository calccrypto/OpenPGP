#include "SHA224.h"

void SHA224::original_h(){
    ctx.h0 = 0xc1059ed8;
    ctx.h1 = 0x367cd507;
    ctx.h2 = 0x3070dd17;
    ctx.h3 = 0xf70e5939;
    ctx.h4 = 0xffc00b31;
    ctx.h5 = 0x68581511;
    ctx.h6 = 0x64f98fa7;
    ctx.h7 = 0xbefa4fa4;
}

SHA224::SHA224() :
    SHA256()
{
    original_h();
}

SHA224::SHA224(const std::string & str) :
    SHA224()
{
    update(str);
}

std::string SHA224::hexdigest(){
    return SHA256::hexdigest().substr(0, 56);
}

unsigned int SHA224::blocksize() const{
    return 512;
}

unsigned int SHA224::digestsize() const{
    return 224;
}