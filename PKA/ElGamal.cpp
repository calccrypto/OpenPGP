#include "ElGamal.h"
std::vector <mpz_class> ElGamal_keygen(unsigned int bits){
    BBS(now()); // seed just in case not seeded

    bits /= 5;
    // random prime q - only used for key generation
    mpz_class q(BBS().rand(bits), 2);
    mpz_nextprime(q.get_mpz_t(), q.get_mpz_t());
    while (q.get_str(2).size() >= bits){
        q.set_str(BBS().rand(bits), 2);
        mpz_nextprime(q.get_mpz_t(), q.get_mpz_t());
    }
    bits *= 5;

    // random prime p = kq + 1
    mpz_class p(BBS().rand(bits), 2);      // pick random starting point
    p = ((p - 1) / q) * q + 1;             // set starting point to value such that p = kq + 1 for some k, while maintaining bitsize
    while (!mpz_probab_prime_p(p.get_mpz_t(), 25)){
        p += q;
    }

    // generator g with order p
    mpz_class g = 1;
    mpz_class h = 1;
    mpz_class exp = (p - 1) / q;
    while (g == 1){
        h++;
        mpz_powm_sec(g.get_mpz_t(), h.get_mpz_t(), exp.get_mpz_t(), p.get_mpz_t());
    }

    // 0 < x < p
    mpz_class x = 0;
    while ((x == 0) || (p <= x)){
        x.set_str(BBS().rand(bits), 2);
    }

    // y = g^x mod p
    mpz_class y;
    mpz_powm_sec(y.get_mpz_t(), g.get_mpz_t(), x.get_mpz_t(), p.get_mpz_t());

    return {p, g, y, x};
}

std::vector <mpz_class> ElGamal_encrypt(const mpz_class & data, const std::vector <mpz_class> & pub){
    mpz_class k(BBS().rand(pub[0].get_str(2).size()), 2);
    k %= pub[0];
    mpz_class r, s;
    mpz_powm_sec(r.get_mpz_t(), pub[1].get_mpz_t(), k.get_mpz_t(), pub[0].get_mpz_t());
    mpz_powm_sec(s.get_mpz_t(), pub[2].get_mpz_t(), k.get_mpz_t(), pub[0].get_mpz_t());
    return {r, (data * s) % pub[0]};
}

std::vector <mpz_class> ElGamal_encrypt(const std::string & data, const std::vector <mpz_class> & pub){
    return ElGamal_encrypt(mpz_class(hexlify(data), 16), pub);
}

std::string ElGamal_decrypt(std::vector <mpz_class> & c, const std::vector <mpz_class> & pri, const std::vector <mpz_class> & pub){
    mpz_class s, m;
    mpz_powm_sec(s.get_mpz_t(), c[0].get_mpz_t(), pri[0].get_mpz_t(), pub[0].get_mpz_t());
    mpz_invert(m.get_mpz_t(), s.get_mpz_t(), pub[0].get_mpz_t());
    m *= c[1];
    m %= pub[0];
    std::string out = m.get_str(16);
    return unhexlify(((out.size() & 1)? "0":"") + out);
}
