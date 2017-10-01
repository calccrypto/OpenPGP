#include "DSA.h"

namespace OpenPGP {
namespace PKA {
namespace DSA {

Values new_public(const uint32_t & L, const uint32_t & N){
//    L = 1024, N = 160
//    L = 2048, N = 224
//    L = 2048, N = 256
//    L = 3072, N = 256
    RNG::BBS(static_cast <MPI> (static_cast <unsigned int> (now()))); // seed just in case not seeded

    // random prime q
    MPI q = bintompi("1" + RNG::BBS().rand(N - 1));
    q = nextprime(q);
    while (bitsize(q) > N){
        q = bintompi("1" + RNG::BBS().rand(N - 1));
        q = nextprime(q);
    }

    // random prime p = kq + 1
    MPI p = bintompi("1" + RNG::BBS().rand(L - 1));                   // pick random starting point
    p = ((p - 1) / q) * q + 1;                                        // set starting point to value such that p = kq + 1 for some k, while maintaining bitsize
    while (!knuth_prime_test(p, 25)){
        p += q;
    }

    // generator g with order q
    MPI g = 1, h = 1;
    MPI exp = (p - 1) / q;
    while (g == 1){
        h++;
        g = powm(h, exp, p);
    }

    return {p, q, g};
}

Values keygen(Values & pub){
    RNG::BBS(static_cast <MPI> (static_cast <unsigned int> (now()))); // seed just in case not seeded

    MPI x = 0;
    std::string test = "testing testing 123"; // a string to test the key with, just in case the key doesn't work for some reason
    unsigned int bits = bitsize(pub[1]) - 1;
    while (true){
        // 0 < x < q
        while ((x == 0) || (pub[1] <= x)){
            x = bintompi(RNG::BBS().rand(bits));
        }

        // y = g^x mod p
        MPI y;
        y = powm(pub[2], x, pub[0]);

        // public key = p, q, g, y
        // private key = x
        pub.push_back(y);

        // check that this key works
        Values rs = sign(test, {x}, pub);

        // if it works, break
        if (verify(test, rs, pub)){
            break;
        }

        pub.pop_back();
    }

    return {x};
}

Values sign(const MPI & data, const Values & pri, const Values & pub, MPI k){
    RNG::BBS(static_cast <MPI> (static_cast <unsigned int> (now()))); // seed just in case not seeded

    bool set_k = (k == 0);

    MPI r = 0, s = 0;
    while ((r == 0) || (s == 0)){
        // 0 < k < q
        if ( set_k ) {
            k = bintompi(RNG::BBS().rand(bitsize(pub[1])));
            k %= pub[1];
        }

        // r = (g^k mod p) mod q
        r = powm(pub[2], k, pub[0]);
        r %= pub[1];

        // if r == 0, don't bother calculating s
        if (r == 0){
            continue;
        }

        // s = k^-1 (m + x * r) mod q
        s = invert(k, pub[1]);
        s *= data + pri[0] * r;
        s %= pub[1];
    }

    return {r, s};
}

Values sign(const std::string & data, const Values & pri, const Values & pub, MPI k){
    MPI m(hexlify(data), 16);
    return sign(rawtompi(data), pri, pub, k);
}

bool verify(const MPI & data, const Values & sig, const Values & pub){
    // 0 < r < q or 0 < s < q
    if (!((0 < sig[0]) && (sig[0] < pub[1])) & !((0 < sig[0]) && (sig[1] < pub[1]))){
        return false;
    }
    // w = s^-1 mod q
    MPI w = invert(sig[1], pub[1]);

    // u1 = H(m) * w mod q
    MPI u1 = (data * w) % pub[1];

    // u2 = r * w mod q
    MPI u2 = (sig[0] * w) % pub[1];

    // v = ((g ^ u1 * y ^ u2) mod p) mod q
    MPI g, y;
    g = powm(pub[2], u1, pub[0]);
    y = powm(pub[3], u2, pub[0]);

    // check v == r
    return ((((g * y) % pub[0]) % pub[1]) == sig[0]);
}

bool verify(const std::string & data, const Values & sig, const Values & pub){
    return verify(rawtompi(data), sig, pub);
}

}
}
}
