#include "mt19937.h"

void mt19937::init(int32_t seed){
    MT[0] = seed;
    for(int i = 1; i < 624; i++){
        MT[i] = (0x6c078965LL * (MT[i - 1] ^ (MT[i - 1] >> 30) ) + i) % (1LL << 32);
    }
    index = 0;
}

void mt19937::generateNumbers(){
    for(int i = 0; i < 624; i++){
        int32_t y = ((MT[i] >> 31) & 1) + (MT[(i + 1) % 624] & (mod32 >> 1)); // not sure if 32nd bit is add or set bit
        MT[i] = MT[(i + 397) % 624] ^ (y >> 1);
        if (y & 1){
            MT[i] ^= 0x9908b0df;
        }
    }
}

mt19937::mt19937(){
    time_t now;
    time(&now);
    init(std::rand() * now);
}

mt19937::mt19937(int32_t seed){
    init(seed);
}

int32_t mt19937::randInt(){
    if (!index){
        generateNumbers();
    }
    int32_t y = MT[index];
    y ^= y >> 11;
    y ^= (y << 7) & 0x9d2c5680;
    y ^= (y << 15) & 0xefc60000;
    y ^= y >> 18;
    index = (index + 1) % 624;
    return y;
}

float mt19937::rand(){
    return (float) (randInt()) / 0xffffffffULL;
}
