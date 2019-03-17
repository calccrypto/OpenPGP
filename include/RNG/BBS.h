/*
BBS.h
Blum Blum Shub by Lenore Blum, Manuel Blum and Michael Shub

Copyright (c) 2013 - 2019 Jason Lee @ calccrypto at gmail.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#ifndef __BBS__
#define __BBS__

#include <string>

#include "Misc/mpi.h"

namespace OpenPGP {
    namespace RNG {
        class BBS{
            private:
                /*
                Only one "real" instance of BBS exists at a time, since
                seeding once will seed for the entire program.
                */
                static bool seeded;               // whether or not BBS is seeded
                static MPI state;                 // current state
                static MPI m;                     // large integer
                const static MPI two;             // constant value of 2
                std::string par;                  // even, odd, or least

                void init(const MPI & SEED, const unsigned int & bits, MPI p, MPI q);
                void r_number();
                bool parity(const std::string & par) const;

            public:
                BBS(...);
                BBS(const MPI & SEED, const unsigned int & bits = 1024, MPI p = 0, MPI q = 0);
                std::string rand_bits (const unsigned int & bits  = 1, const std::string & par = "even");
                std::string rand_bytes(const unsigned int & bytes = 1, const std::string & par = "even");
        };
    }
}

#endif
