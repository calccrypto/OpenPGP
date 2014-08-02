#include "RIPEMD160.h"

uint32_t RIPEMD160::F(const uint32_t & x, const uint32_t & y, const uint32_t & z, const uint8_t round) const{
    if (round < 16){
        return x ^ y ^ z;
    }
    else if (16 <= round && round < 32){
        return (x & y) | (~x & z);
    }
    else if (32 <= round && round < 48){
        return (x | ~y) ^ z;
    }
    else if (48 <= round && round < 64){
        return (x & z) | (y & ~z);
    }
    else{ //if (64 <= round)
        return x ^ (y | ~z);
    }
}

std::string RIPEMD160::to_little_end(const std::string &data) const{
    std::string result;
    for(unsigned int x = 0; x < (data.size() >> 2); x++){
        result += little_end(data.substr(x << 2, 4), 256);
    }
    return result;
}

void RIPEMD160::calc(const std::string &data, context &state) const{
    for(unsigned int i = 0; i < (data.size() >> 6); i++){
        uint32_t a = state.h0, b = state.h1, c = state.h2, d = state.h3, e = state.h4, A = state.h0, B = state.h1, C = state.h2, D = state.h3, E = state.h4;
        uint32_t X[16];
        for(uint8_t j = 0; j < 16; j++){
            X[j] = toint(data.substr(i << 6, 64).substr(j << 2, 4), 256);
        }
        uint32_t T;
        for(uint8_t j = 0; j < 80; j++){
            T = ROL((a + F(b, c, d, j) + X[RIPEMD_r[j]] + RIPEMD160_k[j >> 4]) & mod32, RIPEMD_s[j], 32) + e;
            a = e; e = d; d = ROL(c, 10, 32); c = b; b = T;
            T = ROL((A + F(B, C, D, 79 - j) + X[RIPEMD_R[j]] + RIPEMD160_K[j >> 4]) & mod32, RIPEMD_S[j], 32) + E;
            A = E; E = D; D = ROL(C, 10, 32); C = B; B = T;

        }
        T        = state.h1 + c + D;
        state.h1 = state.h2 + d + E;
        state.h2 = state.h3 + e + A;
        state.h3 = state.h4 + a + B;
        state.h4 = state.h0 + b + C;
        state.h0 = T;
    }
}

RIPEMD160::RIPEMD160() :
    Hash(),
    ctx(RIPEMD_H0, RIPEMD_H1, RIPEMD_H2, RIPEMD_H3, RIPEMD_H4)
{}

RIPEMD160::RIPEMD160(const std::string & str) :
    RIPEMD160()
{
    update(str);
}

void RIPEMD160::update(const std::string & str){
    std::string data = stack + str;
    stack.clear();
    std::string::size_type size = ((data.size() >> 6) << 6);
    if ( std::string::size_type rem = ( data.size() - size ) ){
        stack = data.substr(size, rem);
    }
    calc(to_little_end(data.substr(0, size)), ctx);
    clen += size;
}

std::string RIPEMD160::hexdigest(){
    context tmp = ctx;
    uint16_t size = stack.size();
    std::string last = stack + "\x80" + std::string((((size & 63) > 55)?119:55) - (size & 63), 0);
    last = to_little_end(last);
    std::string temp = unhexlify(makehex(((clen+size) << 3), 16));
    last += temp.substr(4, 4) + temp.substr(0, 4);
    calc(last, tmp);
    return little_end(makehex(tmp.h0, 8)) + little_end(makehex(tmp.h1, 8)) + little_end(makehex(tmp.h2, 8)) + little_end(makehex(tmp.h3, 8)) + little_end(makehex(tmp.h4, 8));
}

unsigned int RIPEMD160::blocksize() const{
    return 512;
}

unsigned int RIPEMD160::digestsize() const{
    return 160;
}