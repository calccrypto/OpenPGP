#include "./SHA384.h"

SHA384::SHA384(const std::string & data){
    h0 = 0xcbbb9d5dc1059ed8ULL;
    h1 = 0x629a292a367cd507ULL;
    h2 = 0x9159015a3070dd17ULL;
    h3 = 0x152fecd8f70e5939ULL;
    h4 = 0x67332667ffc00b31ULL;
    h5 = 0x8eb44a8768581511ULL;
    h6 = 0xdb0c2e0d64f98fa7ULL;
    h7 = 0x47b5481dbefa4fa4ULL;
    update(data);
}

void SHA384::update(const std::string & data){
    bytes += data.size();
    buffer += data;
    run(buffer, h0, h1, h2, h3, h4, h5, h6, h7);
    buffer = buffer.substr(buffer.size() - (buffer.size() & 127), 128);
}

std::string SHA384::hexdigest(){
    uint64_t out0 = h0, out1 = h1, out2 = h2, out3 = h3, out4 = h4, out5 = h5, out6 = h6, out7 = h7;
    run(buffer + "\x80" + std::string((((bytes & 127) > 111)?238:111) - (bytes & 127), 0) + unhexlify(makehex((bytes << 3) & mod64, 32)), out0, out1, out2, out3, out4, out5, out6, out7);
    return (makehex(out0, 16) + makehex(out1, 16) + makehex(out2, 16) + makehex(out3, 16) + makehex(out4, 16) + makehex(out5, 16) + makehex(out6, 16) + makehex(out7, 16)).substr(0, 96);
}

unsigned int SHA384::digestsize(){
    return 384;
}
