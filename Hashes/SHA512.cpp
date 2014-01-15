#include "SHA512.h"

uint64_t SHA512::S0(uint64_t & value){
    return ROR(value, 28, 64) ^ ROR(value, 34, 64) ^ ROR(value, 39, 64);
}

uint64_t SHA512::S1(uint64_t & value){
    return ROR(value, 14, 64) ^ ROR(value, 18, 64) ^ ROR(value, 41, 64);
}

uint64_t SHA512::s0(uint64_t & value){
    return ROR(value, 1, 64) ^ ROR(value, 8, 64) ^ (value >> 7);
}

uint64_t SHA512::s1(uint64_t & value){
    return ROR(value, 19, 64) ^ ROR(value, 61, 64) ^ (value >> 6);
}

void SHA512::original_h(){
    h0 = 0x6a09e667f3bcc908ULL;
    h1 = 0xbb67ae8584caa73bULL;
    h2 = 0x3c6ef372fe94f82bULL;
    h3 = 0xa54ff53a5f1d36f1ULL;
    h4 = 0x510e527fade682d1ULL;
    h5 = 0x9b05688c2b3e6c1fULL;
    h6 = 0x1f83d9abfb41bd6bULL;
    h7 = 0x5be0cd19137e2179ULL;
}

void SHA512::run(const std::string & str){
    original_h();
    uint64_t bytes = str.size();
    std::string data = str + "\x80" + std::string((((bytes & 127) > 111)?238:111) - (bytes & 127), 0) + unhexlify(makehex((uint64_t) bytes << 3, 32));
    for(unsigned int n = 0; n < (data.size() >> 7); n++){
        std::string temp = data.substr(n << 7, 128);
        uint64_t skey[80];
        for(uint8_t x = 0; x < 16; x++){
            skey[x] = toint(temp.substr(x << 3, 8), 256);
        }
        for(uint8_t x = 16; x < 80; x++){
            skey[x] = s1(skey[x - 2]) + skey[x - 7] + s0(skey[x - 15]) + skey[x - 16];
        }
        uint64_t a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
        for(uint8_t x = 0; x < 80; x++){
            uint64_t t1 = h + S1(e) + Ch(e, f, g) + SHA512_K[x] + skey[x];
            uint64_t t2 = S0(a) + Maj(a, b, c);
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

SHA512::SHA512(const std::string & str){
    run(str);
}

std::string SHA512::hexdigest(){
    return makehex(h0, 16) + makehex(h1, 16) + makehex(h2, 16) + makehex(h3, 16) + makehex(h4, 16) + makehex(h5, 16) + makehex(h6, 16) + makehex(h7, 16);
}
