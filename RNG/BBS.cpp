#include "BBS.h"
bool BBS::seeded = false;

mpz_class BBS::state = 0;

mpz_class BBS::m = 0;

void BBS::init(const mpz_class & seed, const unsigned int & bits, mpz_class p, mpz_class q){
    if (!seeded){
        /*
        p and q should be:
            prime
            congruent to 3 mod 4
            gcd(p - 1, q - 1) is small
        */
        gmp_randclass rng(gmp_randinit_default);                 // set up rng for initializing BBS
        rng.seed(rng.get_z_bits(bits));                          // seed itself with random garbage
        if (p == 0){
            p = rng.get_z_bits(bits);
            mpz_nextprime(p.get_mpz_t(), p.get_mpz_t());         // find closest prime
            while ((p & 3) != 3){                                // search for primes that are 3 = p mod 4
                p += 1;
                mpz_nextprime(p.get_mpz_t(), p.get_mpz_t());     // find next prime
            }
        }
        if (q == 0){
            q = rng.get_z_bits(bits);
            mpz_nextprime(q.get_mpz_t(), q.get_mpz_t());         // find closest prime
            mpz_class pq_gcd = 1025;
            while (((q & 3) != 3) && (pq_gcd < 1024)){           // search for primes that are 3 = q mod 4 and gcd(p - 1, q - 1) is small
                q += 1;
                mpz_nextprime(q.get_mpz_t(), q.get_mpz_t());     // find next prime
                mpz_gcd(pq_gcd.get_mpz_t() , mpz_class(p - 1).get_mpz_t(), mpz_class(q - 1).get_mpz_t());
            }
        }
        m = p * q;
        state = seed;
        seeded = true;
    }
}

void BBS::r_number(){
    mpz_powm_sec(state.get_mpz_t(), state.get_mpz_t(), mpz_class(2).get_mpz_t(), m.get_mpz_t());
}

bool BBS::parity(const std::string & par){
    mpz_class value = state;
    if (par == "least"){
        return ((state & 1) == 1);
    }
    else{
        bool t = 0;
        while (value != 0){
            t ^= ((value & 1) == 1);
            value >>= 1;
        }
        t ^= (par == "odd");
        return t;
    }
}

BBS::BBS(...){
    if (!seeded){
        std::cerr << "Error: BBS must be seeded first." << std::endl;
        exit(1);
    }
}

BBS::BBS(const mpz_class & SEED, const unsigned int & bits, mpz_class p, mpz_class q){
    init(SEED, bits, p, q);
}

std::string BBS::rand(const mpz_class & bits, const std::string & par){
    // returns string because SIZE might be larger than 64 bits
    std::string out = "";
    for(mpz_class x = 0; x < bits; x++){
        r_number();
        out += "01"[parity(par)];
    }
    return out;
}
