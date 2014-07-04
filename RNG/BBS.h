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

#include "../common/cryptomath.h"
#include "../mpi.h"
#include "../pgptime.h"

class BBS{
    private:
        static bool seeded;                                   // whether or not BBS is seeded
        static PGPMPI state;                               // current state
        static PGPMPI m;                                   // large integer
        std::string par;                                      // even, odd, or least

        void init(const PGPMPI & SEED, const unsigned int & bits, PGPMPI p, PGPMPI q);
        void r_number();
        bool parity(const std::string & par) const;

    public:
        BBS(...);
        BBS(const PGPMPI & SEED, const unsigned int & bits = 1024, PGPMPI p = 0, PGPMPI q = 0);
        std::string rand(const PGPMPI & bits = 1, const std::string & par = "even");
};
#endif
