#include "./RIPEMD160.h"

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

void RIPEMD160::run(const std::string & data, uint32_t & H0, uint32_t & H1, uint32_t & H2, uint32_t & H3, uint32_t & H4){
    for(unsigned int i = 0; i < (data.size() >> 6); i++){
        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4, A = h0, B = h1, C = h2, D = h3, E = h4;
        uint32_t X[16];
        for(uint8_t j = 0; j < 16; j++){
            X[j] = toint(data.substr(i << 6, 64).substr(j << 2, 4), 256);
        }
        uint32_t T;
        for(uint8_t j = 0; j < 80; j++){
            T = ROL(a + F(b, c, d, j) + X[RIPEMD_r[j]] + RIPEMD160_k[j >> 4], RIPEMD_s[j], 32) + e;
            a = e; e = d; d = ROL(c, 10, 32); c = b; b = T;
            T = ROL(A + F(B, C, D, 79 - j) + X[RIPEMD_R[j]] + RIPEMD160_K[j >> 4], RIPEMD_S[j], 32) + E;
            A = E; E = D; D = ROL(C, 10, 32); C = B; B = T;
        }
        T = H1 + c + D;
        H1 = H2 + d + E;
        H2 = H3 + e + A;
        H3 = H4 + a + B;
        H4 = H0 + b + C;
        H0 = T;
    }
}

RIPEMD160::RIPEMD160(const std::string & data){
    h0 = RIPEMD_H0;
    h1 = RIPEMD_H1;
    h2 = RIPEMD_H2;
    h3 = RIPEMD_H3;
    h4 = RIPEMD_H4;
    update(data);
}

void RIPEMD160::update(const std::string & data){
    bytes += data.size();
    buffer += data;

    std::string temp = "";
    for(unsigned int i = 0; i < ((bytes >> 6) << 6); i += 4){
        temp += little_end(buffer.substr(i, 4), 256);
    }
    run(temp, h0, h1, h2, h3, h4);
    buffer = buffer.substr(buffer.size() - (buffer.size() & 63), 64);
}

std::string RIPEMD160::hexdigest(){
    uint32_t out0 = h0, out1 = h1, out2 = h2, out3 = h3, out4 = h4;
    std::string data = buffer + "\x80" + std::string((((bytes & 63) > 55)?119:55) - (bytes & 63), 0);

    std::string temp = "";
    for(unsigned int i = 0; i < data.size(); i += 4){
        temp += little_end(data.substr(i, 4), 256);
    }

    std::string len = unhexlify(makehex(bytes << 3, 16));
    temp += len.substr(4, 4) + len.substr(0, 4);

    run(temp, out0, out1, out2, out3, out4);

    return little_end(makehex(out0, 8), 16) + little_end(makehex(out1, 8), 16) + little_end(makehex(out2, 8), 16) + little_end(makehex(out3, 8), 16) + little_end(makehex(out4, 8), 16);
}

unsigned int RIPEMD160::blocksize(){
    return 512;
}

unsigned int RIPEMD160::digestsize(){
    return 160;
}
