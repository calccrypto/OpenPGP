#include "SHA384.h"

void SHA384::original_h(){
    ctx.h0 = 0xcbbb9d5dc1059ed8ULL;
    ctx.h1 = 0x629a292a367cd507ULL;
    ctx.h2 = 0x9159015a3070dd17ULL;
    ctx.h3 = 0x152fecd8f70e5939ULL;
    ctx.h4 = 0x67332667ffc00b31ULL;
    ctx.h5 = 0x8eb44a8768581511ULL;
    ctx.h6 = 0xdb0c2e0d64f98fa7ULL;
    ctx.h7 = 0x47b5481dbefa4fa4ULL;
}

SHA384::SHA384() :
    SHA512()
{
    original_h();
}

SHA384::SHA384(const std::string & str) :
    SHA384()
{
    update(str);
}

std::string SHA384::hexdigest(){
    return SHA512::hexdigest().substr(0, 96);
}

unsigned int SHA384::blocksize() const{
    return 1024;
}

unsigned int SHA384::digestsize() const{
    return 384;
}