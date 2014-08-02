#include "SHA256.h"

uint32_t SHA256::S0(const uint32_t & value) const{
    return ROR(value, 2, 32) ^ ROR(value, 13, 32) ^ ROR(value, 22, 32);
}

uint32_t SHA256::S1(const uint32_t & value) const{
    return ROR(value, 6, 32) ^ ROR(value, 11, 32) ^ ROR(value, 25, 32);
}

uint32_t SHA256::s0(const uint32_t & value) const{
    return ROR(value, 7, 32) ^ ROR(value, 18, 32) ^ (value >> 3);
}

uint32_t SHA256::s1(const uint32_t & value) const{
    return ROR(value, 17, 32) ^ ROR(value, 19, 32) ^ (value >> 10);
}

void SHA256::original_h(){
    ctx.h0 = 0x6a09e667;
    ctx.h1 = 0xbb67ae85;
    ctx.h2 = 0x3c6ef372;
    ctx.h3 = 0xa54ff53a;
    ctx.h4 = 0x510e527f;
    ctx.h5 = 0x9b05688c;
    ctx.h6 = 0x1f83d9ab;
    ctx.h7 = 0x5be0cd19;
}

void SHA256::calc(const std::string &data, context &state) const{
    for(unsigned int n = 0; n < (data.size() >> 6); n++){
        std::string temp = data.substr(n << 6, 64);
        uint32_t skey[64];
        for(uint8_t x = 0; x < 16; x++){
            skey[x] = toint(temp.substr(x << 2, 4), 256);
        }
        for(uint8_t x = 16; x < 64; x++){
            skey[x] = s1(skey[x - 2]) + skey[x - 7] + s0(skey[x - 15]) + skey[x - 16];
        }
        uint32_t a = state.h0, b = state.h1, c = state.h2, d = state.h3, e = state.h4, f = state.h5, g = state.h6, h = state.h7;
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
        state.h0 += a; state.h1 += b; state.h2 += c; state.h3 += d; state.h4 += e; state.h5 += f; state.h6 += g; state.h7 += h;
    }
}

SHA256::SHA256() :
    Hash(),
    ctx()
{
    original_h();
}

SHA256::SHA256(const std::string & str) :
    SHA256()
{
    update(str);
}

void SHA256::update(const std::string &str){
    std::string data = stack + str;
    stack.clear();
    std::string::size_type size = ((data.size() >> 6) << 6);
    if ( std::string::size_type rem = ( data.size() - size ) ){
        stack = data.substr(size, rem);
    }
    calc(data.substr(0, size), ctx);
    clen += size;
}

std::string SHA256::hexdigest(){
    context tmp = ctx;
    uint32_t size = stack.size();
    std::string last = stack + "\x80" + std::string((((size & 63) > 55)?119:55) - (size & 63), 0) + unhexlify(makehex((clen+size) << 3, 16));
    calc(last, tmp);
    return makehex(tmp.h0, 8) + makehex(tmp.h1, 8) + makehex(tmp.h2, 8) + makehex(tmp.h3, 8) + makehex(tmp.h4, 8) + makehex(tmp.h5, 8) + makehex(tmp.h6, 8) + makehex(tmp.h7, 8);
}

unsigned int SHA256::blocksize() const{
    return 512;
}

unsigned int SHA256::digestsize() const{
    return 256;
}