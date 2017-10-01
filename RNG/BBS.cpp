#include "BBS.h"

namespace OpenPGP {
namespace RNG {

bool BBS::seeded = false;

MPI BBS::state = 0;

MPI BBS::m = 0;

const MPI BBS::two = 2;

void BBS::init(const MPI & seed, const unsigned int & bits, MPI p, MPI q){
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
            p = nextprime(p);                                    // find closest prime
            while ((p & 3) != 3){                                // search for primes that are 3 = p mod 4
                p += 1;
                p = nextprime(p);                                // find next prime
            }
        }
        if (q == 0){
            q = rng.get_z_bits(bits);
            q = nextprime(q);                                    // find closest prime
            MPI pq_gcd = 1025;
            while (((q & 3) != 3) && (pq_gcd < 1024)){           // search for primes that are 3 = q mod 4 and gcd(p - 1, q - 1) is small
                q += 1;
                q = nextprime(q);                                // find next prime
                pq_gcd = mpigcd(p-1, q-1);
            }
        }
        m = p * q;
        state = seed;
        seeded = true;
    }
}

void BBS::r_number(){
    state = powm(state, two, m);
}

bool BBS::parity(const std::string & par) const{
    MPI value = state;
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

BBS::BBS(...)
    : par()
{
    if (!seeded){
        throw std::runtime_error("Error: BBS must be seeded first.");
    }
}

BBS::BBS(const MPI & SEED, const unsigned int & bits, MPI p, MPI q)
    : par()
{
    init(SEED, bits, p, q);
}

std::string BBS::rand(const unsigned int & bits, const std::string & par){
    // returns string because SIZE might be larger than 64 bits
    std::string out(bits, '0');
    for(char & c : out){
        r_number();
        c += parity(par);
    }
    return out;
}

}
}