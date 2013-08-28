#include "SHA224.h"

void SHA224::original_h(){
    h0 = 0xc1059ed8;
    h1 = 0x367cd507;
    h2 = 0x3070dd17;
    h3 = 0xf70e5939;
    h4 = 0xffc00b31;
    h5 = 0x68581511;
    h6 = 0x64f98fa7;
    h7 = 0xbefa4fa4;
}

SHA224::SHA224(const std::string & str){
    update(str);
}

std::string SHA224::hexdigest(){
    return (makehex(h0, 8) + makehex(h1, 8) + makehex(h2, 8) + makehex(h3, 8) + makehex(h4, 8) + makehex(h5, 8) + makehex(h6, 8) + makehex(h7, 8)).substr(0, 56);
}

unsigned int SHA224::digestsize(){
    return 224;
}
