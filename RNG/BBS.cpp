#include "BBS.h"
void BBS::init(int64_t SEED, int SIZE, std::string PAR, int64_t p, int64_t q){
    /*
    parity: even, odd, or least

    getpq: auto or manual;
        manual assumes the p and q values are:
            prime
            congruent to 3 mod 4
            gcd(p - 1, q - 1) is small
    */
    seed = SEED;
    par = PAR;
    size = SIZE;

    srand(time(NULL));
    if (!p){
        p = std::rand();
        p -= not(p & 1);
        while ((!MillerRabin(p)) && ((p & 3) != 3)){
            p -= 4;
        }
    }
    if (!q){
        q = std::rand();
        q -= not(q & 1);
        while ((!MillerRabin(q)) && ((q & 3) != 3)){ /*&& (gcd(p - 1, q - 1) > 10)*/
            q -= 4;
        }
    }
    m = p * q;
}

void BBS::r_number(){
    seed = POW(seed, 2, m);
}

bool BBS::parity(){
    uint64_t value = seed;
    if (par == "least"){
        return seed & 1;
    }
    else{
        bool t = 0;
        while (value){
            t ^= value & 1;
            value >>= 1;
        }
        t ^= (par == "odd");
        return t;
    }
}

BBS::BBS(unsigned int SIZE, std::string PAR, int64_t p, int64_t q){
    time_t now;
    time(&now);
    init(std::rand() * now, SIZE, PAR, p, q);
}

BBS::BBS(int64_t SEED, int SIZE, std::string PAR, int64_t p, int64_t q){
    init(SEED, SIZE, PAR, p, q);
}

std::string BBS::rand(){
    // returns string because SIZE might be larger than 64 bits
    // use 'toint(BBS().rand(), 2)' to get integer value
    std::string out = "";
    for(int64_t x = 0; x < size; x++){
        r_number();
        out += "01"[parity()];
    }
    return out;
}
