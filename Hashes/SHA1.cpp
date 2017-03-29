#include "SHA1.h"

void SHA1::calc(const std::string & data, context & state) const {
    for(unsigned int n = 0; n < (data.size() >> 6); n++){
        std::string temp = data.substr(n << 6, 64);
        uint32_t skey[80];
        for(uint8_t x = 0; x < 16; x++){
            skey[x] = toint(temp.substr(x << 2, 4), 256);
        }
        for(uint8_t x = 16; x < 80; x++){
            skey[x] = ROL((skey[x - 3] ^ skey[x - 8] ^ skey[x - 14] ^ skey[x - 16]), 1, 32);
        }
        uint32_t a = state.h0, b = state.h1, c = state.h2, d = state.h3, e = state.h4;
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
        state.h0 += a;
        state.h1 += b;
        state.h2 += c;
        state.h3 += d;
        state.h4 += e;
    }
}

SHA1::SHA1() :
    MerkleDamgard(),
    ctx(0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
{}

SHA1::SHA1(const std::string & str) :
    SHA1()
{
    update(str);
}

void SHA1::update(const std::string & str){
    std::string data = stack + str;
    stack.clear();
    std::string::size_type size = ((data.size() >> 6) << 6);
    if ( std::string::size_type rem = ( data.size() - size ) ){
        stack = data.substr(size, rem);
    }
    calc(data.substr(0, size), ctx);
    clen += size;
}

std::string SHA1::hexdigest(){
    context tmp = ctx;
    uint16_t size = stack.size();
    std::string last = stack + "\x80" + std::string((((size & 63) > 55)?119:55) - (size & 63), 0) + unhexlify(makehex((clen+size) << 3, 16));
    calc(last, tmp);
    return makehex(tmp.h0, 8) + makehex(tmp.h1, 8) + makehex(tmp.h2, 8) + makehex(tmp.h3, 8) + makehex(tmp.h4, 8);
}

std::size_t SHA1::blocksize() const {
    return 512;
}

std::size_t SHA1::digestsize() const {
    return 160;
}