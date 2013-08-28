#include "SHA384.h"

void SHA384::original_h(){
    h0 = 0xcbbb9d5dc1059ed8ULL;
    h1 = 0x629a292a367cd507ULL;
    h2 = 0x9159015a3070dd17ULL;
    h3 = 0x152fecd8f70e5939ULL;
    h4 = 0x67332667ffc00b31ULL;
    h5 = 0x8eb44a8768581511ULL;
    h6 = 0xdb0c2e0d64f98fa7ULL;
    h7 = 0x47b5481dbefa4fa4ULL;
}

SHA384::SHA384(const std::string & str){
    update(str);
}

std::string SHA384::hexdigest(){
    return (makehex(h0, 16) + makehex(h1, 16) + makehex(h2, 16) + makehex(h3, 16) + makehex(h4, 16) + makehex(h5, 16) + makehex(h6, 16) + makehex(h7, 16)).substr(0, 96);
}

unsigned int SHA384::digestsize(){
    return 384;
}
