#include "ElGamal.h"

namespace OpenPGP {
namespace PKA {
namespace ElGamal {

Values keygen(unsigned int bits){
    RNG::BBS(static_cast <MPI> (static_cast <unsigned int> (now()))); // seed just in case not seeded

    bits /= 5;
    // random prime q - only used for key generation
    MPI q = bintompi(RNG::BBS().rand(bits));
    q = nextprime(q);
    while (bitsize(q) > bits){
        q = bintompi(RNG::BBS().rand(bits));
        q = nextprime(q);
    }
    bits *= 5;

    // random prime p = kq + 1
    MPI p = bintompi("1" + RNG::BBS().rand(bits - 1));                // pick random starting point
    p = ((p - 1) / q) * q + 1;                                        // set starting point to value such that p = kq + 1 for some k, while maintaining bitsize
    while (!knuth_prime_test(p, 25)){
        p += q;
    }

    // generator g with order p
    MPI g = 1;
    MPI h = 1;
    MPI exp = (p - 1) / q;
    while (g == 1){
        g = powm(++h, exp, p);
    }

    // 0 < x < p
    MPI x = 0;
    while ((x == 0) || (p <= x)){
        x = bintompi(RNG::BBS().rand(bits));
    }

    // y = g^x mod p
    MPI y;
    y = powm(g, x, p);

    return {p, g, y, x};
}

Values encrypt(const MPI & data, const Values & pub){
    RNG::BBS(static_cast <MPI> (static_cast <unsigned int> (now()))); // seed just in case not seeded
    MPI k = bintompi(RNG::BBS().rand(bitsize(pub[0])));
    k %= pub[0];
    MPI r, s;
    r = powm(pub[1], k, pub[0]);
    s = powm(pub[2], k, pub[0]);
    return {r, (data * s) % pub[0]};
}

Values encrypt(const std::string & data, const Values & pub){
    return encrypt(rawtompi(data), pub);
}

std::string decrypt(const Values & c, const Values & pri, const Values & pub){
    MPI s, m;
    s = powm(c[0], pri[0], pub[0]);
    m = invert(s, pub[0]);
    m *= c[1];
    m %= pub[0];
    return mpitoraw(m);
}

}
}
}