#include "MD5.h"

std::string MD5::to_little_end(const std::string & data) const {
    std::string result;
    for(unsigned int x = 0; x < (data.size() >> 2); x++){
        result += little_end(data.substr(x << 2, 4), 256);
    }
    return result;
}

void MD5::calc(const std::string & data, context & state) const {
    for(unsigned int i = 0; i < (data.size() >> 6); i++){
        uint32_t a = state.h0, b = state.h1, c = state.h2, d = state.h3;
        uint32_t w[16];
        for(uint8_t x = 0; x < 16; x++){
            w[x] = toint(data.substr(i << 6, 64).substr(x << 2, 4), 256);
        }
        for(uint8_t x = 0; x < 64; x++){
            uint32_t f = 0, g = 0;
            if (x < 16){
                f = (b & c) | ((~ b) & d);
                g = x;
            }
            else if ((16 <= x) && (x < 32)){
                f = (d & b) | ((~ d) & c);
                g = (5 * x + 1) & 15;
            }
            else if ((32 <= x) && (x < 48)){
                f = b ^ c ^ d;
                g = (3 * x + 5) & 15;
            }
            else if (48 <= x){
                f = c ^ (b | (~ d));
                g = (7 * x) & 15;
            }
            uint32_t t = d;
            d = c;
            c = b;
            b += ROL(a + f + MD5_K[x] + w[g], MD5_R[x], 32);
            a = t;
        }
        state.h0 += a;
        state.h1 += b;
        state.h2 += c;
        state.h3 += d;
    }
}

MD5::MD5() :
    MerkleDamgard(),
    ctx(0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)
{}

MD5::MD5(const std::string & str) :
    MD5()
{
    update(str);
}

void MD5::update(const std::string & str){
    std::string data = stack + str;
    stack.clear();
    std::string::size_type size = ((data.size() >> 6) << 6);
    if ( std::string::size_type rem = ( data.size() - size ) ){
        stack = data.substr(size, rem);
    }
    calc(to_little_end(data.substr(0, size)), ctx);
    clen += size;
}

std::string MD5::hexdigest(){
    context tmp = ctx;
    uint16_t size = stack.size();
    std::string last = stack + "\x80" + std::string((((size & 63) > 55)?119:55) - (size & 63), 0);
    last = to_little_end(last);
    std::string temp = unhexlify(makehex((clen+size) << 3, 16));
    last += temp.substr(4, 4) + temp.substr(0, 4);
    calc(last, tmp);
    return little_end(makehex(tmp.h0, 8)) + little_end(makehex(tmp.h1, 8)) + little_end(makehex(tmp.h2, 8)) + little_end(makehex(tmp.h3, 8));
}

std::size_t MD5::blocksize() const {
    return 512;
}

std::size_t MD5::digestsize() const {
    return 128;
}