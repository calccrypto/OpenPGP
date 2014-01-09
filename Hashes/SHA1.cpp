#include "SHA1.h"

void SHA1::run(const std::string & data, uint32_t & H0, uint32_t & H1, uint32_t & H2, uint32_t & H3, uint32_t & H4){
    unsigned int n = 0;
    for(; n < (data.size() >> 6); n++){
        uint32_t skey[80];
        for(uint8_t x = 0; x < 16; x++){
            skey[x] = toint(data.substr((n << 6) + (x << 2), 4), 256);
        }
        for(uint8_t x = 16; x < 80; x++){
            skey[x] = ROL((skey[x - 3] ^ skey[x - 8] ^ skey[x - 14] ^ skey[x - 16]), 1, 32);
        }
        uint32_t a = H0, b = H1, c = H2, d = H3, e = H4;
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
            uint32_t t = ROL(a, 5, 32) + f + e + k + skey[j];
            e = d;
            d = c;
            c = ROL(b, 30, 32);
            b = a;
            a = t;
        }
        H0 += a;
        H1 += b;
        H2 += c;
        H3 += d;
        H4 += e;
    }
}

SHA1::SHA1(const std::string & data){
    h0 = 0x67452301;
    h1 = 0xEFCDAB89;
    h2 = 0x98BADCFE;
    h3 = 0x10325476;
    h4 = 0xC3D2E1F0;
    update(data);
}

void SHA1::update(const std::string & data){
    bytes += data.size();
    buffer += data;
    run(buffer, h0, h1, h2, h3, h4);
    buffer = buffer.substr(buffer.size() - (buffer.size() & 63), 64);
}

std::string SHA1::hexdigest(){
    uint32_t out0 = h0, out1 = h1, out2 = h2, out3 = h3, out4 = h4;
    run(buffer + "\x80" + std::string((((bytes & 63) > 55)?119:55) - (bytes & 63), 0) + unhexlify(makehex((bytes << 3) & mod64, 16)), out0, out1, out2, out3, out4);
    return makehex(out0, 8) + makehex(out1, 8) + makehex(out2, 8) + makehex(out3, 8) + makehex(out4, 8);
}

unsigned int SHA1::blocksize(){
    return 512;
}

unsigned int SHA1::digestsize(){
    return 160;
}
