#include "DSA.h"
std::vector <PGPMPI> new_DSA_public(const uint32_t & L, const uint32_t & N){
//    L = 1024, N = 160
//    L = 2048, N = 224
//    L = 2048, N = 256
//    L = 3072, N = 256
    BBS(static_cast <PGPMPI> (static_cast <unsigned int> (now()))); // seed just in case not seeded

    // random prime q
    PGPMPI q = bintompi("1" + BBS().rand(N - 1));
    q = nextprime(q);
    while (bitsize(q) > N){
        q = bintompi("1" + BBS().rand(N - 1));
        q = nextprime(q);
    }

    // random prime p = kq + 1
    PGPMPI p = bintompi("1" + BBS().rand(L - 1));      // pick random starting point
    p = ((p - 1) / q) * q + 1;                    // set starting point to value such that p = kq + 1 for some k, while maintaining bitsize
    while (!knuth_prime_test(p, 25)){
        p += q;
    }

    // generator g with order q
    PGPMPI g = 1, h = 1;
    PGPMPI exp = (p - 1) / q;
    while (g == 1){
        h++;
        g = powm(h, exp, p);
    }
    return {p, q, g};
}

std::vector <PGPMPI> DSA_keygen(std::vector <PGPMPI> & pub){
    BBS(static_cast <PGPMPI> (static_cast <unsigned int> (now()))); // seed just in case not seeded

    PGPMPI x = 0;
    std::string test = "testing testing 123"; // a string to test the key with, just in case the key doesnt work for some reason
    unsigned int bits = bitsize(pub[1]) - 1;
    while (true){
        // 0 < x < q
        while ((x == 0) || (pub[1] <= x)){
            x = bintompi(BBS().rand(bits));
        }

        // y = g^x mod p
        PGPMPI y;
        y = powm(pub[2], x, pub[0]);

        // public key = p, q, g, y
        // private key = x
        pub.push_back(y);

        // check that this key works
        std::vector <PGPMPI> rs = DSA_sign(test, {x}, pub);

        // if it works, break
        if (DSA_verify(test, rs, pub)){
            break;
        }
        pub.pop_back();
    }
    return {x};
}

std::vector <PGPMPI> DSA_sign(const PGPMPI & data, const std::vector <PGPMPI> & pri, const std::vector <PGPMPI> & pub, PGPMPI k){
    BBS(static_cast <PGPMPI> (static_cast <unsigned int> (now()))); // seed just in case not seeded

    bool set_k = (k == 0);

    PGPMPI r = 0, s = 0;
    while ((r == 0) || (s == 0)){
        // 0 < k < q
        if ( set_k ) {
            k = bintompi(BBS().rand(bitsize(pub[1])));
            k %= pub[1];
        }

        // r = (g^k mod p) mod q
        r = powm(pub[2], k, pub[0]);
        r %= pub[1];

        // if r == 0, dont bother calculating s
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

std::vector <PGPMPI> DSA_sign(const std::string & data, const std::vector <PGPMPI> & pri, const std::vector <PGPMPI> & pub, PGPMPI k){
    PGPMPI m(hexlify(data), 16);
    return DSA_sign(rawtompi(data), pri, pub, k);
}

bool DSA_verify(const PGPMPI & data, const std::vector <PGPMPI> & sig, const std::vector <PGPMPI> & pub){
    // 0 < r < q or 0 < s < q
    if (!((0 < sig[0]) && (sig[0] < pub[1])) & !((0 < sig[0]) && (sig[1] < pub[1]))){
        return false;
    }
    // w = s^-1 mod q
    PGPMPI w = invert(sig[1], pub[1]);

    // u1 = H(m) * w mod q
    PGPMPI u1 = (data * w) % pub[1];

    // u2 = r * w mod q
    PGPMPI u2 = (sig[0] * w) % pub[1];

    // v = ((g ^ u1 * y ^ u2) mod p) mod q
    PGPMPI g, y;
    g = powm(pub[2], u1, pub[0]);
    y = powm(pub[3], u2, pub[0]);

    // check v == r
    return ((((g * y) % pub[0]) % pub[1]) == sig[0]);
}

bool DSA_verify(const std::string & data, const std::vector <PGPMPI> & sig, const std::vector <PGPMPI> & pub){
    return DSA_verify(rawtompi(data), sig, pub);
}
