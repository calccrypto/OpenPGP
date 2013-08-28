#include "MD5.h"

void MD5::run(){
    h0 = 0x67452301;
    h1 = 0xefcdab89;
    h2 = 0x98badcfe;
    h3 = 0x10325476;
    std::string data = total;
    unsigned int length = (data.size() << 3) & mod32;
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
            b += ROL((a + f + MD5_K[x] + w[g]) & mod32, MD5_R[x], 32);
            a = t;
        }
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
    }
}

MD5::MD5(const std::string & str){
    update(str);
}

std::string MD5::hexdigest(){
    return little_end(makehex(h0 & mod32, 8)) + little_end(makehex(h1 & mod32, 8)) + little_end(makehex(h2 & mod32, 8)) + little_end(makehex(h3 & mod32, 8));
}

unsigned int MD5::blocksize(){
    return 512;
}

unsigned int MD5::digestsize(){
    return 128;
}
