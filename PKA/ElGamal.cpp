#include "ElGamal.h"
std::vector <mpz_class> ElGamal_keygen(const unsigned int & bits){
    BBS(now()); // seed just in case not seeded

    // random prime p
    mpz_class p(BBS().rand(bits), 2);
    mpz_nextprime(p.get_mpz_t(), p.get_mpz_t());
    while (p.get_str(2).size() > bits){
        p.set_str(BBS().rand(bits), 2);
        mpz_nextprime(p.get_mpz_t(), p.get_mpz_t());
    }

    // random prime q - only used for finding g
    mpz_class q(BBS().rand(bits * 5), 2);
    mpz_nextprime(q.get_mpz_t(), q.get_mpz_t());

    // generator g with order p
    mpz_class g = 1;
    mpz_class h = 1;
    mpz_class exp = (q - 1) / p;
    while (g == 1){
        h++;
        mpz_powm(g.get_mpz_t(), h.get_mpz_t(), exp.get_mpz_t(), q.get_mpz_t());
    }

    // 0 < x < p
    mpz_class x = 0;
    while ((x == 0) || (p <= x)){
        x.set_str(BBS().rand(bits), 2);
    }

    // y = g^x mod p
    mpz_class y;
    mpz_powm(y.get_mpz_t(), g.get_mpz_t(), x.get_mpz_t(), p.get_mpz_t());

    return {p, g, y, x};
}

std::vector <mpz_class> ElGamal_encrypt(const mpz_class & data, const std::vector <mpz_class> & pub){
    mpz_class k(BBS().rand(pub[0].get_str(2).size()), 2);
    k %= pub[0];
    mpz_class r, s;
    mpz_powm(r.get_mpz_t(), pub[1].get_mpz_t(), k.get_mpz_t(), pub[0].get_mpz_t());
    mpz_powm(s.get_mpz_t(), pub[2].get_mpz_t(), k.get_mpz_t(), pub[0].get_mpz_t());
    return {r, (data * s) % pub[0]};
}

std::vector <mpz_class> ElGamal_encrypt(const std::string & data, const std::vector <mpz_class> & pub){
    return ElGamal_encrypt(mpz_class(hexlify(data), 16), pub);
}

std::string ElGamal_decrypt(std::vector <mpz_class> & c, const std::vector <mpz_class> & pri, const std::vector <mpz_class> & pub){
    mpz_class s, m;
    mpz_powm(s.get_mpz_t(), c[0].get_mpz_t(), pri[0].get_mpz_t(), pub[0].get_mpz_t());
    mpz_invert(m.get_mpz_t(), s.get_mpz_t(), pub[0].get_mpz_t());
    m *= c[1];
    m %= pub[0];
    std::string out = m.get_str(16);
    return unhexlify(((out.size() & 1)? "0":"") + out);
}
