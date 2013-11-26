#include "DSA.h"
std::vector <integer> new_DSA_public(uint32_t L, uint32_t N){
//    L = 1024, N = 160
//    L = 2048, N = 224
//    L = 2048, N = 256
//    L = 3072, N = 256
    integer q(BBS(N).rand(), 2);
    q += !(q & 1);
    while (!MillerRabin(q)){
        q += 2;
    }
    integer p(BBS(L).rand(), 2);
    p += !(p & 1);
    p--;
    p = ((p - 1) / q) * q + 1;
    while (!MillerRabin(p)){
        p += q;
    }
    integer g = 1;
    integer h = 2;
    integer exp = (p - 1) / q;
    while (g == 1){
        g = POW(h++, exp, p);
    }
    return {p, q, g};
}

integer DSA_keygen(std::vector <integer> & pub){
    integer x;
    std::string test = "0123456789abcdef";
    while (true){
        x = integer(BBS(pub[2].bits() - 1).rand(), 2);
        pub.push_back(POW(pub[3], x, pub[1]));
        std::vector <integer> rs = DSA_sign(test, {x}, pub);
        if (DSA_verify(test, rs, pub)){
            break;
        }
    }
    return x;
}
std::vector <integer> DSA_sign(std::string & data, const std::vector <integer> & pri, const std::vector <integer> & pub){

    integer k, r, s;
    while (!r || !s){
        k = (integer(BBS(pub[1].bits()).rand(), 2) % (pub[1] - 1)) + 1;
        r = POW(pub[2], k, pub[0]) % pub[1];
        if (!r){
            continue;
        }
        s = (invmod(pub[1], k) * (integer(data, 256) + pri[0] * r)) % pub[1];
    }
    return {r, s};
}

bool DSA_verify(std::string & data, const std::vector <integer> & sig, const std::vector <integer> & pub){
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
    integer w = invmod(pub[1], sig[1]);
    integer u1 = (integer(data, 256) * w) % pub[1];
    integer u2 = (sig[0] * w) % pub[1];
    return ((((POW(pub[2], u1, pub[0]) * POW(pub[3], u2, pub[0])) % pub[0]) % pub[1]) == sig[0]);
}
