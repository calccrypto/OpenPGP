#include "DSA.h"
std::vector <mpz_class> new_DSA_public(uint32_t L, uint32_t N){
//    L = 1024, N = 160
//    L = 2048, N = 224
//    L = 2048, N = 256
//    L = 3072, N = 256
    BBS(now()); // seed just in case not seeded

    mpz_class p, q;

    while (true){
        q = mpz_class(BBS().rand(N), 2);
        mpz_nextprime(q.get_mpz_t(), q.get_mpz_t());
        if (q.get_str(2).size() < N){
            break;
        }
    }

    while (true){
        p = mpz_class(BBS().rand(L), 2);
        mpz_nextprime(p.get_mpz_t(), p.get_mpz_t());
        if (((p - 1) % q) == 0){
            break;
        }
    }

    mpz_class g = 1;
    mpz_class h = 2;
    mpz_class exp = (p - 1) / q;
    while (g == 1){
        mpz_powm_sec(g.get_mpz_t(), h.get_mpz_t(), exp.get_mpz_t(), p.get_mpz_t());
        h++;
    }
    return {p, q, g};
}

mpz_class DSA_keygen(std::vector <mpz_class> & pub){
    mpz_class x, t;
    std::string test = h;
    while (true){
        x = mpz_class(BBS().rand((makebin(pub[2]).size() - 1)), 2);
        mpz_powm_sec(t.get_mpz_t(), pub[3].get_mpz_t(), x.get_mpz_t(), pub[1].get_mpz_t());
        pub.push_back(t);
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
        k = (mpz_class(BBS().rand(pub[1].get_str(2).size()), 2) % (pub[1] - 1)) + 1;
        mpz_powm_sec(r.get_mpz_t(), pub[2].get_mpz_t(), k.get_mpz_t(), pub[0].get_mpz_t());
        r %= pub[1];
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

    mpz_class g, y;
    mpz_powm_sec(g.get_mpz_t(), pub[2].get_mpz_t(), u1.get_mpz_t(), pub[0].get_mpz_t());
    mpz_powm_sec(y.get_mpz_t(), pub[3].get_mpz_t(), u2.get_mpz_t(), pub[0].get_mpz_t());

    return (((g * y) % pub[1]) == sig[0]);
}
