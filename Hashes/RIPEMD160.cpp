#include "RIPEMD160.h"

uint32_t RIPEMD160::F(const uint32_t & x, const uint32_t & y, const uint32_t & z, const uint8_t round){
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

void RIPEMD160::run(){
    h0 = RIPEMD_H0; h1 = RIPEMD_H1; h2 = RIPEMD_H2; h3 = RIPEMD_H3; h4 = RIPEMD_H4;
    std::string data = total;
    unsigned int length = (data.size() << 3) & mod64;
    data += "\x80";
    while (data.size() % 64 != 56){
        data += std::string("\x00", 1);
    }
    std::string temp = "";
    for(unsigned int x = 0; x < data.size() >> 2; x++){
        temp += little_end(data.substr(x << 2, 4), 256);
    }
    data = temp;
    temp = unhexlify(makehex(length, 16));
    data += temp.substr(4, 4) + temp.substr(0, 4);
    for(unsigned int i = 0; i < (data.size() >> 6); i++){
        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4, A = h0, B = h1, C = h2, D = h3, E = h4;
        uint32_t X[16];
        for(uint8_t j = 0; j < 16; j++){
            X[j] = toint(data.substr(i << 6, 64).substr(j << 2, 4), 256);
        }
        uint32_t T;
        for(uint8_t j = 0; j < 80; j++){
            T = (ROL((a + F(b, c, d, j) + X[RIPEMD_r[j]] + RIPEMD160_k[j >> 4]) & mod32, RIPEMD_s[j], 32) + e) & mod32;
            a = e; e = d; d = ROL(c, 10, 32); c = b; b = T;
            T = (ROL((A + F(B, C, D, 79 - j) + X[RIPEMD_R[j]] + RIPEMD160_K[j >> 4]) & mod32, RIPEMD_S[j], 32) + E) & mod32;
            A = E; E = D; D = ROL(C, 10, 32); C = B; B = T;

        }
        T = h1 + c + D;
        h1 = h2 + d + E;
        h2 = h3 + e + A;
        h3 = h4 + a + B;
        h4 = h0 + b + C;
        h0 = T;
    }
}

RIPEMD160::RIPEMD160(const std::string & str){
    update(str);
}

std::string RIPEMD160::hexdigest(){
    return little_end(makehex(h0, 8)) + little_end(makehex(h1, 8)) + little_end(makehex(h2, 8)) + little_end(makehex(h3, 8)) + little_end(makehex(h4, 8));
}

unsigned int RIPEMD160::blocksize(){
    return 512;
}

unsigned int RIPEMD160::digestsize(){
    return 160;
}
