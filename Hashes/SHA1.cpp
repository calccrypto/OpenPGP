#include "SHA1.h"

SHA1::SHA1(const std::string & str){
    h0 = 0x67452301;
    h1 = 0xEFCDAB89;
    h2 = 0x98BADCFE;
    h3 = 0x10325476;
    h4 = 0xC3D2E1F0;
    uint32_t bytes = str.size();
    std::string data = str + "\x80" + std::string((((bytes & 63) > 55)?119:55) - (bytes & 63), 0) + unhexlify(makehex(bytes << 3, 16));
    for(unsigned int n = 0; n < (data.size() >> 6); n++){
        std::string temp = data.substr(n << 6, 64);
        uint32_t skey[80];
        for(uint8_t x = 0; x < 16; x++){
            skey[x] = toint(temp.substr(x << 2, 4), 256);
        }
        for(uint8_t x = 16; x < 80; x++){
            skey[x] = ROL((skey[x - 3] ^ skey[x - 8] ^ skey[x - 14] ^ skey[x - 16]), 1, 32);
        }
        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
        for(uint8_t j = 0; j < 80; j++){
            uint32_t f = 0, k = 0;
            if (j <= 19){
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            }
            if (20 <= j && j <= 39){
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            }
            if (40 <= j && j <= 59){
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            }
            if (60 <= j && j <= 79){
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            uint32_t temp = ROL(a, 5, 32) + f + e + k + skey[j];
            e = d;
            d = c;
            c = ROL(b, 30, 32);
            b = a;
            a = temp;
        }
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }
}

std::string SHA1::hexdigest(){
    return makehex(h0, 8) + makehex(h1, 8) + makehex(h2, 8) + makehex(h3, 8) + makehex(h4, 8);
}
