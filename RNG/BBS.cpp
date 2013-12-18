#include "BBS.h"
void BBS::init(mpz_class SEED, unsigned int SIZE, std::string PAR, mpz_class p, mpz_class q){
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
    if (p == 0){
        p = std::rand();
        p -= ((p & 1) == 0);
        while ((!MillerRabin(p)) && ((p & 3) != 3)){
            p -= 4;
        }
    }
    if (q == 0){
        q = std::rand();
        q -= ((q & 1) == 0);
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
    mpz_class value = seed;
    if (par == "least"){
        return ((seed & 1) == 1);
    }
    else{
        bool t = 0;
        while (value != 0){
            t ^= ((value & 1) == 1);
            value >>= 1;
        }
        t ^= (par == "odd");
        return t;
    }
}

BBS::BBS(unsigned int SIZE, std::string PAR, mpz_class p, mpz_class q){
    time_t now;
    time(&now);
    init(mpz_class(std::rand() * (unsigned int) now), SIZE, PAR, p, q);
}

BBS::BBS(mpz_class SEED, unsigned int SIZE, std::string PAR, mpz_class p, mpz_class q){
    init(SEED, SIZE, PAR, p, q);
}

std::string BBS::rand(){
    // returns string because SIZE might be larger than 64 bits
    std::string out = "";
    for(int64_t x = 0; x < size; x++){
        r_number();
        out += "01"[parity()];
    }
    return out;
}
