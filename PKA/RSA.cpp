#include "RSA.h"

PKA::Values RSA_keygen(const uint32_t & bits){
    BBS(static_cast <PGPMPI> (static_cast <unsigned int> (now()))); // seed just in case not seeded

    PGPMPI p = 3, q = 3;
    while (p == q){
        p = bintompi(BBS().rand(bits));
        q = bintompi(BBS().rand(bits));
        p = nextprime(p);
        q = nextprime(q);
    }

    PGPMPI n = p * q;
    PGPMPI tot = (p - 1) * (q - 1);
    PGPMPI e = bintompi(BBS().rand(bits));
    e += ((e & 1) == 0);
    PGPMPI gcd = 0;
    while (gcd != 1){
        e += 2;
        gcd = mpigcd(tot, e);
    }
    PGPMPI d;
    d = invert(e, tot);
    return {n, e, d}; // split this into {n, e} and {d}
}

PGPMPI RSA_encrypt(const PGPMPI & data, const PKA::Values & pub){
    return powm(data, pub[1], pub[0]);
}

PGPMPI RSA_encrypt(const std::string & data, const PKA::Values & pub){
    return powm(rawtompi(data), pub[1], pub[0]);
}

PGPMPI RSA_decrypt(const PGPMPI & data, const PKA::Values & pri, const PKA::Values & pub){
    return powm(data, pri[0], pub[0]);
}

PGPMPI RSA_sign(const PGPMPI & data, const PKA::Values & pri, const PKA::Values & pub){
    return RSA_decrypt(data, pri, pub);
}

PGPMPI RSA_sign(const std::string & data, const PKA::Values & pri, const PKA::Values & pub){
    return RSA_decrypt(rawtompi(data), pri, pub);
}

bool RSA_verify(const PGPMPI & data, const PKA::Values & signature, const PKA::Values & pub){
    return (RSA_encrypt(signature[0], pub) == data);
}

bool RSA_verify(const std::string & data, const PKA::Values & signature, const PKA::Values & pub){
    return RSA_verify(rawtompi(data), signature, pub);
}
