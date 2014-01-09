#include "./SHA224.h"

SHA224::SHA224(const std::string & data){
    h0 = 0xc1059ed8;
    h1 = 0x367cd507;
    h2 = 0x3070dd17;
    h3 = 0xf70e5939;
    h4 = 0xffc00b31;
    h5 = 0x68581511;
    h6 = 0x64f98fa7;
    h7 = 0xbefa4fa4;
    update(data);
}

std::string SHA224::hexdigest(){
    uint32_t out0 = h0, out1 = h1, out2 = h2, out3 = h3, out4 = h4, out5 = h5, out6 = h6, out7 = h7;
    run(buffer + "\x80" + std::string((((bytes & 63) > 55)?119:55) - (bytes & 63), 0) + unhexlify(makehex((bytes << 3) & mod64, 16)), out0, out1, out2, out3, out4, out5, out6, out7);
    return (makehex(out0, 8) + makehex(out1, 8) + makehex(out2, 8) + makehex(out3, 8) + makehex(out4, 8) + makehex(out5, 8) + makehex(out6, 8) + makehex(out7, 8)).substr(0, 56);
}

unsigned int SHA224::digestsize(){
    return 224;
}
