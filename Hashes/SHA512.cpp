#include "SHA512.h"

uint64_t SHA512::S0(uint64_t & value) const{
    return ROR(value, 28, 64) ^ ROR(value, 34, 64) ^ ROR(value, 39, 64);
}

uint64_t SHA512::S1(uint64_t & value) const{
    return ROR(value, 14, 64) ^ ROR(value, 18, 64) ^ ROR(value, 41, 64);
}

uint64_t SHA512::s0(uint64_t & value) const{
    return ROR(value, 1, 64) ^ ROR(value, 8, 64) ^ (value >> 7);
}

uint64_t SHA512::s1(uint64_t & value) const{
    return ROR(value, 19, 64) ^ ROR(value, 61, 64) ^ (value >> 6);
}

void SHA512::original_h(){
    ctx.h0 = 0x6a09e667f3bcc908ULL;
    ctx.h1 = 0xbb67ae8584caa73bULL;
    ctx.h2 = 0x3c6ef372fe94f82bULL;
    ctx.h3 = 0xa54ff53a5f1d36f1ULL;
    ctx.h4 = 0x510e527fade682d1ULL;
    ctx.h5 = 0x9b05688c2b3e6c1fULL;
    ctx.h6 = 0x1f83d9abfb41bd6bULL;
    ctx.h7 = 0x5be0cd19137e2179ULL;
}

void SHA512::calc(const std::string & data, context & state) const{
    for(unsigned int n = 0; n < (data.size() >> 7); n++){
        std::string temp = data.substr(n << 7, 128);
        uint64_t skey[80];
        for(uint8_t x = 0; x < 16; x++){
            skey[x] = toint(temp.substr(x << 3, 8), 256);
        }
        for(uint8_t x = 16; x < 80; x++){
            skey[x] = s1(skey[x - 2]) + skey[x - 7] + s0(skey[x - 15]) + skey[x - 16];
        }
        uint64_t a = state.h0, b = state.h1, c = state.h2, d = state.h3, e = state.h4, f = state.h5, g = state.h6, h = state.h7;
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
        state.h0 += a; state.h1 += b; state.h2 += c; state.h3 += d; state.h4 += e; state.h5 += f; state.h6 += g; state.h7 += h;
    }
}

SHA512::SHA512() :
    Hash(),
    ctx()
{
    original_h();
}

SHA512::SHA512(const std::string & str) :
    SHA512()
{
    update(str);
}

void SHA512::update(const std::string &str){
    std::string data = stack + str;
    stack.clear();
    std::string::size_type size = ((data.size() >> 7) << 7);
    if ( std::string::size_type rem = ( data.size() - size ) ){
        stack = data.substr(size, rem);
    }
    calc(data.substr(0, size), ctx);
    clen += size;
}

std::string SHA512::hexdigest(){
    context tmp = ctx;
    uint64_t size = stack.size();
    std::string last = stack + "\x80" + std::string((((size & 127) > 111)?239:111) - (size & 127), 0) + unhexlify(makehex((clen+size) << 3, 32));
    calc(last, tmp);
    return makehex(tmp.h0, 16) + makehex(tmp.h1, 16) + makehex(tmp.h2, 16) + makehex(tmp.h3, 16) + makehex(tmp.h4, 16) + makehex(tmp.h5, 16) + makehex(tmp.h6, 16) + makehex(tmp.h7, 16);
}

unsigned int SHA512::blocksize() const{
    return 1024;
}

unsigned int SHA512::digestsize() const{
    return 512;
}