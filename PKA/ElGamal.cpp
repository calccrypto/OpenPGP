#include "ElGamal.h"
std::vector <PGPMPI> ElGamal_keygen(unsigned int bits){
    BBS(static_cast <PGPMPI> (static_cast <unsigned int> (now()))); // seed just in case not seeded

    bits /= 5;
    // random prime q - only used for key generation
    PGPMPI q = bintompi(BBS().rand(bits));
    q = nextprime(q);
    while (bitsize(q) > bits){
        q = bintompi(BBS().rand(bits));
        q = nextprime(q);
    }
    bits *= 5;

    // random prime p = kq + 1
    PGPMPI p = bintompi("1" + BBS().rand(bits - 1));      // pick random starting point
    p = ((p - 1) / q) * q + 1;                       // set starting point to value such that p = kq + 1 for some k, while maintaining bitsize
    while (!knuth_prime_test(p, 25)){
        p += q;
    }

    // generator g with order p
    PGPMPI g = 1;
    PGPMPI h = 1;
    PGPMPI exp = (p - 1) / q;
    while (g == 1){
        h++;
        g = powm(h, exp, p);
    }

    // 0 < x < p
    PGPMPI x = 0;
    while ((x == 0) || (p <= x)){
        x = bintompi(BBS().rand(bits));
    }

    // y = g^x mod p
    PGPMPI y;
    y = powm(g, x, p);

    return {p, g, y, x};
}

std::vector <PGPMPI> ElGamal_encrypt(const PGPMPI & data, const std::vector <PGPMPI> & pub){
    BBS(static_cast <PGPMPI> (static_cast <unsigned int> (now()))); // seed just in case not seeded
    PGPMPI k = bintompi(BBS().rand(bitsize(pub[0])));
    k %= pub[0];
    PGPMPI r, s;
    r = powm(pub[1], k, pub[0]);
    s = powm(pub[2], k, pub[0]);
    return {r, (data * s) % pub[0]};
}

std::vector <PGPMPI> ElGamal_encrypt(const std::string & data, const std::vector <PGPMPI> & pub){
    return ElGamal_encrypt(rawtompi(data), pub);
}

std::string ElGamal_decrypt(std::vector <PGPMPI> & c, const std::vector <PGPMPI> & pri, const std::vector <PGPMPI> & pub){
    PGPMPI s, m;
    s = powm(c[0], pri[0], pub[0]);
    m = invert(s, pub[0]);
    m *= c[1];
    m %= pub[0];
    return mpitoraw(m);
}
