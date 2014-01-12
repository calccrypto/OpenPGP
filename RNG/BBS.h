/*
Blum Blum Shub by Lenore Blum, Manuel Blum and Michael Shub

Only one "real" instance of BBS exists at a time, since
seeding once will seed for the entire program.
*/

#ifndef __BBS__
#define __BBS__

#include <algorithm>
#include <ctime>
#include <iostream>

#include <gmpxx.h>

#include "../common/cryptomath.h"
#include "../pgptime.h"

class BBS{
    private:
        static bool seeded;                                   // whether or not BBS is seeded
        static mpz_class state;                               // current state
        static mpz_class m;                                   // large integer
        std::string par;                                      // even, odd, or least

        void init(const mpz_class & SEED, const unsigned int & bits, mpz_class p, mpz_class q);
        void r_number();
        bool parity(const std::string & par);

    public:
        BBS(...);
        BBS(const mpz_class & SEED, const unsigned int & bits = 1024, mpz_class p = 0, mpz_class q = 0);
        std::string rand(const mpz_class & bits = 1, const std::string & par = "even");
};
#endif
