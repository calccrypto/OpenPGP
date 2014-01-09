#include "./MD5.h"

void MD5::run(const std::string & data, uint32_t & H0, uint32_t & H1, uint32_t & H2, uint32_t & H3){
    for(unsigned int i = 0; i < (data.size() >> 6); i++){
        uint32_t a = h0, b = h1, c = h2, d = h3;
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
        H0 += a;
        H1 += b;
        H2 += c;
        H3 += d;
    }
}

MD5::MD5(const std::string & data){
    h0 = 0x67452301;
    h1 = 0xefcdab89;
    h2 = 0x98badcfe;
    h3 = 0x10325476;

    update(data);
}

void MD5::update(const std::string & data){
    bytes += data.size();
    buffer += data;

    std::string temp = "";
    for(unsigned int i = 0; i < ((bytes >> 6) << 6); i += 4){
        temp += little_end(buffer.substr(i, 4), 256);
    }
    run(temp, h0, h1, h2, h3);
    buffer = buffer.substr(buffer.size() - (buffer.size() & 63), 64);
}

std::string MD5::hexdigest(){
    uint32_t out0 = h0, out1 = h1, out2 = h2, out3 = h3;
    std::string data = buffer + "\x80" + std::string((((bytes & 63) > 55)?119:55) - (bytes & 63), 0);

    std::string temp = "";
    for(unsigned int i = 0; i < data.size(); i += 4){
        temp += little_end(data.substr(i, 4), 256);
    }

    std::string len = unhexlify(makehex(bytes << 3, 16));
    temp += len.substr(4, 4) + len.substr(0, 4);

    run(temp, out0, out1, out2, out3);

    return little_end(makehex(out0, 8), 16) + little_end(makehex(out1, 8), 16) + little_end(makehex(out2, 8), 16) + little_end(makehex(out3, 8), 16);
}

unsigned int MD5::blocksize(){
    return 512;
}

unsigned int MD5::digestsize(){
    return 128;
}
