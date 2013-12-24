#include "ElGamal.h"
std::vector <mpz_class> ElGamal_keygen(unsigned int bits){
    BBS(now()); // seed just in case not seeded

    mpz_class p = 2;
    mpz_class q(BBS().rand(bits - 1), 2);
    // all primes are of the form 6k - 1 and 6k + 1
    q *= 6;
    bool d = 0;
    while (!mpz_probab_prime_p(p.get_mpz_t(), 25)){
        while (true){
            mpz_class q1 = q - 1;
            if (mpz_probab_prime_p(q1.get_mpz_t(), 25)){
                d = 0;
                break;
            }
            mpz_class q2 = q + 1;
            if (mpz_probab_prime_p(q2.get_mpz_t(), 25)){
                d = 1;
                break;
            }
            q -= 6;
        }
        p = ((q + (d?1:-1)) << 1) + 1;
        q -= 6;
    }
    mpz_class g(BBS().rand(bits), 2);
    mpz_class pow = 1;
    while (((g % p) == 1) || (pow == 1) ||/* (POW(g, k, p) == 1) ||*/ (((p - 1) % g) == 0)){
        mpz_powm(pow.get_mpz_t(), g.get_mpz_t(), mpz_class(2).get_mpz_t(), p.get_mpz_t());
    }
    mpz_class x(BBS().rand(bits), 2);
    x %= p - 1;
    ++x;

    mpz_class y;
    mpz_powm(y.get_mpz_t(), g.get_mpz_t(), x.get_mpz_t(), p.get_mpz_t());
    return {p, g, y, x};
}

std::vector <mpz_class> ElGamal_encrypt(mpz_class & data, const std::vector <mpz_class> & pub){
    mpz_class k(BBS().rand(pub[0].get_str(2).size()), 2);
    k %= pub[0];
    mpz_class r, s;
    mpz_powm(r.get_mpz_t(), pub[1].get_mpz_t(), k.get_mpz_t(), pub[0].get_mpz_t());
    mpz_powm(s.get_mpz_t(), pub[2].get_mpz_t(), k.get_mpz_t(), pub[0].get_mpz_t());
    return {r, (data * s) % pub[0]};
}

std::vector <mpz_class> ElGamal_encrypt(std::string & data, const std::vector <mpz_class> & pub){
    mpz_class k(BBS().rand(pub[0].get_str(2).size()), 2);
    k %= pub[0];
    mpz_class r, s;
    mpz_powm(r.get_mpz_t(), pub[1].get_mpz_t(), k.get_mpz_t(), pub[0].get_mpz_t());
    mpz_powm(s.get_mpz_t(), pub[2].get_mpz_t(), k.get_mpz_t(), pub[0].get_mpz_t());
    return {r, (mpz_class(hexlify(data), 16) * s) % pub[0]};
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
