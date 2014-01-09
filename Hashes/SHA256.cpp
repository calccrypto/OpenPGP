#include "./SHA256.h"

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

void SHA256::run(const std::string & data, uint32_t & H0, uint32_t & H1, uint32_t & H2, uint32_t & H3, uint32_t & H4, uint32_t & H5, uint32_t & H6, uint32_t & H7){
    for(unsigned int n = 0; n < (data.size() >> 6); n++){
        std::string temp = data.substr(n << 6, 64);
        uint32_t skey[64];
        for(uint8_t x = 0; x < 16; x++){
            skey[x] = toint(temp.substr(x << 2, 4), 256);
        }
        for(uint8_t x = 16; x < 64; x++){
            skey[x] = s1(skey[x - 2]) + skey[x - 7] + s0(skey[x - 15]) + skey[x - 16];
        }
        uint32_t a = H0, b = H1, c = H2, d = H3, e = H4, f = H5, g = H6, h = H7;
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
        H0 += a; H1 += b; H2 += c; H3 += d; H4 += e; H5 += f; H6 += g; H7 += h;
    }
}

SHA256::SHA256(const std::string & data){
    h0 = 0x6a09e667;
    h1 = 0xbb67ae85;
    h2 = 0x3c6ef372;
    h3 = 0xa54ff53a;
    h4 = 0x510e527f;
    h5 = 0x9b05688c;
    h6 = 0x1f83d9ab;
    h7 = 0x5be0cd19;
    update(data);
}

void SHA256::update(const std::string & data){
    bytes += data.size();
    buffer += data;
    run(buffer, h0, h1, h2, h3, h4, h5, h6, h7);
    buffer = buffer.substr(buffer.size() - (buffer.size() & 63), 64);
}

std::string SHA256::hexdigest(){
    uint32_t out0 = h0, out1 = h1, out2 = h2, out3 = h3, out4 = h4, out5 = h5, out6 = h6, out7 = h7;
    run(buffer + "\x80" + std::string((((bytes & 63) > 55)?119:55) - (bytes & 63), 0) + unhexlify(makehex((bytes << 3) & mod64, 16)), out0, out1, out2, out3, out4, out5, out6, out7);
    return makehex(out0, 8) + makehex(out1, 8) + makehex(out2, 8) + makehex(out3, 8) + makehex(out4, 8) + makehex(out5, 8) + makehex(out6, 8) + makehex(out7, 8);
}

unsigned int SHA256::blocksize(){
    return 512;
}

unsigned int SHA256::digestsize(){
    return 256;
}
