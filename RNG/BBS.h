// Blum Blum Shub by Lenore Blum, Manuel Blum and Michael Shub

#include <algorithm>
#include <ctime>
#include <iostream>

#include <gmpxx.h>

#ifndef __BBS__
#define __BBS__

#include "../common/cryptomath.h"
#include "primalitytest.h"

class BBS{
    private:
        int64_t size;
        mpz_class seed, m;
        std::string par;

        void init(mpz_class SEED, unsigned int SIZE, std::string PAR, mpz_class p = 0, mpz_class q = 0);
        void r_number();
        bool parity();

    public:
        BBS(unsigned int SIZE = 32, std::string PAR = "even", mpz_class p = 0, mpz_class q = 0);
        BBS(mpz_class SEED, unsigned int SIZE = 32, std::string PAR = "even", mpz_class p = 0, mpz_class q = 0);
        std::string rand();
};
#endif
