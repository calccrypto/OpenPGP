#include "ElGamal.h"
std::vector <mpz_class> ElGamal_keygen(unsigned int bits){
    mpz_class p = 2;
    mpz_class q(BBS(bits - 1).rand(), 2);
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
    mpz_class g(BBS(bits).rand(), 2);
    while (((g % p) == 1) || (POW(g, 2, p) == 1) ||/* (POW(g, k, p) == 1) ||*/ (((p - 1) % g) == 0))
        g = mpz_class(BBS(bits).rand(), 2) % p;
    mpz_class x(BBS(bits).rand(), 2);
    x %= p - 1;
    ++x;
    return {p, g, POW(g, x, p), x};
}

std::vector <mpz_class> ElGamal_encrypt(mpz_class & data, const std::vector <mpz_class> & pub){
    mpz_class y(BBS((unsigned int) makebin(pub[0]).size()).rand(), 2);
    y %= pub[0];
    return {POW(pub[1], y, pub[0]), (data * POW(pub[2], y, pub[0])) % pub[0]};
}

std::vector <mpz_class> ElGamal_encrypt(std::string & data, const std::vector <mpz_class> & pub){
    mpz_class y(BBS((unsigned int) makebin(pub[0]).size()).rand(), 2);
    y %= pub[0];
    return {POW(pub[1], y, pub[0]), (mpz_class(data, 256) * POW(pub[2], y, pub[0])) % pub[0]};
}

std::string ElGamal_decrypt(std::vector <mpz_class> & c, const std::vector <mpz_class> & pri, const std::vector <mpz_class> & pub){
//    std::string out = ((c[1] * POW(c[0], pub[0] - 1 - pri[0], pub[0])) % pub[0]).get_str(16);
//    out = std::string(out.size() & 1, '0') + out;
//    return unhexlify(out);
    return "";
}
