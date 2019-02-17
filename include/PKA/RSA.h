/*
RSA.h
RSA algorithm

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

#ifndef __RSA__
#define __RSA__

#include "RNG/RNGs.h"
#include "common/includes.h"
#include "Misc/mpi.h"
#include "Misc/pgptime.h"
#include "PKA.h"

namespace OpenPGP {
    namespace PKA {
        namespace RSA {
            // Generate RSA key values
            Values keygen(const uint32_t & bits = 2048);

            // Encrypt data
            MPI encrypt(const MPI & data, const Values & pub);
            MPI encrypt(const std::string & data, const Values & pub);

            // Decrypt data
            MPI decrypt(const MPI & data, const Values & pri, const Values & pub);

            // Sign data
            MPI sign(const MPI & data, const Values & pri, const Values & pub);
            MPI sign(const std::string & data, const Values & pri, const Values & pub);

            // Verify signature
            bool verify(const MPI & data, const Values & signature, const Values & pub);
            bool verify(const std::string & data, const Values & signature, const Values & pub);
        }
    }
}

#endif
