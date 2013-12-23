#include "DSA.h"
std::vector <mpz_class> new_DSA_public(uint32_t L, uint32_t N){
//    L = 1024, N = 160
//    L = 2048, N = 224
//    L = 2048, N = 256
//    L = 3072, N = 256
    mpz_class q(BBS().rand(N), 2);
    q += !((q & 1) == 1);
    while (!MillerRabin(q)){
        q += 2;
    }
    mpz_class p(BBS().rand(L), 2);
    p += !((p & 1) == 1);
    p--;
    p = ((p - 1) / q) * q + 1;
    while (!MillerRabin(p)){
        p += q;
    }
    mpz_class g = 1;
    mpz_class h = 2;
    mpz_class exp = (p - 1) / q;
    while (g == 1){
        g = POW(h++, exp, p);
    }
    return {p, q, g};
}

mpz_class DSA_keygen(std::vector <mpz_class> & pub){
    mpz_class x;
    std::string test = "0123456789abcdef";
    while (true){
        x = mpz_class(BBS().rand((makebin(pub[2]).size() - 1)), 2);
        pub.push_back(POW(pub[3], x, pub[1]));
        std::vector <mpz_class> rs = DSA_sign(test, {x}, pub);
        if (DSA_verify(test, rs, pub)){
            break;
        }
    }
    return x;
}
std::vector <mpz_class> DSA_sign(std::string & data, const std::vector <mpz_class> & pri, const std::vector <mpz_class> & pub){

    mpz_class k, r, s;
    while ((r == 0) || (s == 0)){
        k = (mpz_class(BBS().rand(makebin(pub[1]).size()), 2) % (pub[1] - 1)) + 1;
        r = POW(pub[2], k, pub[0]) % pub[1];
        if (r == 0){
            continue;
        }
        s = (invmod(pub[1], k) * (mpz_class(data, 256) + pri[0] * r)) % pub[1];
    }
    return {r, s};
}

bool DSA_verify(std::string & data, const std::vector <mpz_class> & sig, const std::vector <mpz_class> & pub){
    /*
        0 < r < q or 0 < s < q
        w = s^-1 mod q
        u1 = H(m) * w mod q
        u2 = r * w mod q
        v = ((g ^ u1 * y ^ u2) mod p) mod q
        check v == r
    */
    if (!((0 < sig[0]) && (sig[0] < pub[1])) & !((0 < sig[0]) && (sig[1] < pub[1]))){
        return false;
    }
    mpz_class w = invmod(pub[1], sig[1]);
    mpz_class u1 = (mpz_class(data, 256) * w) % pub[1];
    mpz_class u2 = (sig[0] * w) % pub[1];
    return ((((POW(pub[2], u1, pub[0]) * POW(pub[3], u2, pub[0])) % pub[0]) % pub[1]) == sig[0]);
}
