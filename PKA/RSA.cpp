#include "RSA.h"

PKA::Values RSA_keygen(const uint32_t & bits){
    BBS(static_cast <PGPMPI> (static_cast <unsigned int> (now()))); // seed just in case not seeded

    PGPMPI p = 3;
    PGPMPI q = 3;

    // gpg only accepts 'n's of certain sizes
    #ifdef GPG_COMPATIBLE
    const uint32_t bitsize_1 = bits << 1;       // 1024, 2048, 4096
    const uint32_t bitsize_2 = bitsize_1 - 8;   // 1016, 2040, 4088

    if ((bitsize_1 != 1024) && (bitsize_1 != 2048) && (bitsize_1 != 4096)){
        return {};
    }

    PGPMPI n;
    while (bitsize(n) != (bits << 1)){
        p = nextprime(bintompi("1" + BBS().rand(bits - 1)));
        q = nextprime(bintompi("1" + BBS().rand(bits - 1)));
        n = p * q;
    }
    #else
    while (p == q){
        p = nextprime(bintompi(BBS().rand(bits)));
        q = nextprime(bintompi(BBS().rand(bits)));
    }
    const PGPMPI n = p * q;
    #endif

    // required by RFC 4880 sec 5.5.3
    if (p > q){
        mpiswap(p, q);
    }

    const PGPMPI tot = (p - 1) * (q - 1);

    PGPMPI e = bintompi(BBS().rand(bits));
    e += ((e & 1) == 0);
    while (mpigcd(tot, e) != 1){
        e += 2;
    }

    // split this into {n, e} and {d, p, q, u}
    return {n, e, invert(e, tot), p, q, invert(p, q)};
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
