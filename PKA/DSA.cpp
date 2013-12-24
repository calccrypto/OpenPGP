#include "DSA.h"
std::vector <mpz_class> new_DSA_public(const uint32_t & L, const uint32_t & N){
//    L = 1024, N = 160
//    L = 2048, N = 224
//    L = 2048, N = 256
//    L = 3072, N = 256
    BBS(now()); // seed just in case not seeded

    mpz_class q(BBS().rand(N), 2);
    mpz_nextprime(q.get_mpz_t(), q.get_mpz_t());

    while (q.get_str(2).size() >= N){
        q.set_str(BBS().rand(N), 2);
        mpz_nextprime(q.get_mpz_t(), q.get_mpz_t());
    }

    mpz_class p(BBS().rand(L), 2);      // pick random starting point
    p = ((p - 1) / q) * q + 1;                      // set starting point to value such that p = kq + 1 for some k, while maintaining bitsize
    while (!mpz_probab_prime_p(p.get_mpz_t(), 25)){
        p += q;
    }

    mpz_class g = 1;
    mpz_class h = 1;
    mpz_class exp = (p - 1) / q;
    while (g == 1){
        h++;
        mpz_powm(g.get_mpz_t(), h.get_mpz_t(), exp.get_mpz_t(), p.get_mpz_t());
    }
    return {p, q, g};
}

std::vector <mpz_class> DSA_keygen(std::vector <mpz_class> & pub){
    mpz_class x = 0;
    std::string test = h;
    unsigned int bits = pub[1].get_str(2).size() - 1;
    while (true){
        // 0 < x < q
        while ((pub[1] <= x) || (x == 0)){
            x.set_str(BBS().rand(bits), 2);
        }

        // y = g^x mod p
        mpz_class y;
        mpz_powm(y.get_mpz_t(), pub[2].get_mpz_t(), x.get_mpz_t(), pub[0].get_mpz_t());

        // public key = p, q, g, y
        // private key = x
        pub.push_back(y);

        // check that this key works
        std::vector <mpz_class> rs = DSA_sign(test, {x}, pub);

        // if it works, break
        if (DSA_verify(test, rs, pub)){
            break;
        }
        pub.pop_back();
    }
    return {x};
}

std::vector <mpz_class> DSA_sign(std::string & data, const std::vector <mpz_class> & pri, const std::vector <mpz_class> & pub){
    mpz_class k, r = 0, s = 0;
    while ((r == 0) || (s == 0)){
        // 0 < k < q
        k.set_str(BBS().rand(pub[1].get_str(2).size()), 2) % pub[1];

        // r = (g^k mod p) mod q
        mpz_powm(r.get_mpz_t(), pub[2].get_mpz_t(), k.get_mpz_t(), pub[0].get_mpz_t());
        r %= pub[1];

        // if r == 0, dont bother calculating s
        if (r == 0){
            continue;
        }

        // s = k^-1 (m + x * r) mod q
        mpz_invert(s.get_mpz_t(), k.get_mpz_t(), pub[1].get_mpz_t());
        s *= mpz_class(hexlify(data), 16) + pri[0] * r;
        s %= pub[1];
    }
    return {r, s};
}

bool DSA_verify(std::string & data, const std::vector <mpz_class> & sig, const std::vector <mpz_class> & pub){
    // 0 < r < q or 0 < s < q
    if (!((0 < sig[0]) && (sig[0] < pub[1])) & !((0 < sig[0]) && (sig[1] < pub[1]))){
        return false;
    }
    // w = s^-1 mod q
    mpz_class w;
    mpz_invert(w.get_mpz_t(), sig[1].get_mpz_t(), pub[1].get_mpz_t());

    // u1 = H(m) * w mod q
    mpz_class u1 = (mpz_class(hexlify(data), 16) * w) % pub[1];

    // u2 = r * w mod q
    mpz_class u2 = (sig[0] * w) % pub[1];

    // v = ((g ^ u1 * y ^ u2) mod p) mod q
    mpz_class g, y;
    mpz_powm(g.get_mpz_t(), pub[2].get_mpz_t(), u1.get_mpz_t(), pub[0].get_mpz_t());
    mpz_powm(y.get_mpz_t(), pub[3].get_mpz_t(), u2.get_mpz_t(), pub[0].get_mpz_t());

    // check v == r
    return ((((g * y) % pub[0]) % pub[1]) == sig[0]);
}
