#include "SHA256.h"

uint32_t SHA256::S0(const uint32_t & value){
    return ROR(value, 2, 32) ^ ROR(value, 13, 32) ^ ROR(value, 22, 32);
}

uint32_t SHA256::S1(const uint32_t & value){
    return ROR(value, 6, 32) ^ ROR(value, 11, 32) ^ ROR(value, 25, 32);
}

uint32_t SHA256::s0(const uint32_t & value){
    return ROR(value, 7, 32) ^ ROR(value, 18, 32) ^ (value >> 3);
}

uint32_t SHA256::s1(const uint32_t & value){
    return ROR(value, 17, 32) ^ ROR(value, 19, 32) ^ (value >> 10);
}

void SHA256::original_h(){
    h0 = 0x6a09e667;
    h1 = 0xbb67ae85;
    h2 = 0x3c6ef372;
    h3 = 0xa54ff53a;
    h4 = 0x510e527f;
    h5 = 0x9b05688c;
    h6 = 0x1f83d9ab;
    h7 = 0x5be0cd19;
}

void SHA256::run(const std::string & str){
    original_h();
    uint32_t bytes = str.size();
    std::string data = str + "\x80" + std::string((((bytes & 63) > 55)?119:55) - (bytes & 63), 0) + unhexlify(makehex((uint64_t) bytes << 3, 16));
    for(unsigned int n = 0; n < (data.size() >> 6); n++){
        std::string temp = data.substr(n << 6, 64);
        uint32_t skey[64];
        for(uint8_t x = 0; x < 16; x++){
            skey[x] = toint(temp.substr(x << 2, 4), 256);
        }
        for(uint8_t x = 16; x < 64; x++){
            skey[x] = s1(skey[x - 2]) + skey[x - 7] + s0(skey[x - 15]) + skey[x - 16];
        }
        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
        for(uint8_t x = 0; x < 64; x++){
            uint32_t t1 = h + S1(e) + Ch(e, f, g) + SHA256_K[x] + skey[x];
            uint32_t t2 = S0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        h0 += a; h1 += b; h2 += c; h3 += d; h4 += e; h5 += f; h6 += g; h7 += h;
    }
}

SHA256::SHA256(const std::string & str){
    run(str);
}

std::string SHA256::hexdigest(){
    return makehex(h0, 8) + makehex(h1, 8) + makehex(h2, 8) + makehex(h3, 8) + makehex(h4, 8) + makehex(h5, 8) + makehex(h6, 8) + makehex(h7, 8);
}
