#include "ElGamal.h"
std::vector <integer> ElGamal_keygen(unsigned int bits){
    integer p = 2;
    integer q(BBS(bits - 1).rand(), 2);
    // all primes are of the form 6k - 1 and 6k + 1
    q *= 6;
    bool d = 0;
    while (!MillerRabin(p)){
        while (true){
            if (MillerRabin(q - 1)){
                d = 0;
                break;
            }
            if (MillerRabin(q + 1)){
                d = 1;
                break;
            }
            q -= 6;
        }
        p = ((q + (d?1:-1)) << 1) + 1;
        q -= 6;
    }
    integer g(BBS(bits).rand(), 2);
    while (((g % p) == 1) || (POW(g, 2, p) == 1) ||/* (POW(g, k, p) == 1) ||*/ (!((p - 1) % g)))
        g = integer(BBS(bits).rand(), 2) % p;
    integer x(BBS(bits).rand(), 2);
    x %= p - 1;
    ++x;
    return {p, g, POW(g, x, p), x};
}

std::vector <integer> ElGamal_encrypt(std::string data, std::vector <integer> & pub){
    integer y(BBS(pub[0].bits()).rand(), 2);
    y %= pub[0];
    return {POW(pub[1], y, pub[0]), (integer(data, 256) * POW(pub[2], y, pub[0])) % pub[0]};
}

std::string ElGamal_decrypt(std::vector <integer> & c, std::vector <integer> & pub, integer pri){
    return ((c[1] * POW(c[0], pub[0] - 1 - pri, pub[0])) % pub[0]).str(256);
}
