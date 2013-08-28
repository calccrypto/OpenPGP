// Blum Blum Shub by Lenore Blum, Manuel Blum and Michael Shub

#include <algorithm>
#include <ctime>
#include <iostream>

#ifndef __BBS__
#define __BBS__

#include "../common/cryptomath.h"
#include "primalitytest.h"

class BBS{
    private:
        int64_t seed, size, m;
        std::string par;

        void init(int64_t SEED, int SIZE, std::string PAR, int64_t p = 0, int64_t q = 0);
        void r_number();
        bool parity();

    public:
        BBS(unsigned int SIZE = 32, std::string PAR = "even", int64_t p = 0, int64_t q = 0);
        BBS(int64_t SEED, int SIZE = 32, std::string PAR = "even", int64_t p = 0, int64_t q = 0);
        std::string rand();
};
#endif
