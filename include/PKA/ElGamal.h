/*
ElGamal.h
ElGamal encryption algorithm

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

#ifndef __ELGAMAL__
#define __ELGAMAL__

#include "Misc/mpi.h"
#include "PKA/PKA.h"

namespace OpenPGP {
    namespace PKA {
        namespace ElGamal {
            // Generate ElGamal key values
            Values keygen(unsigned int bits = 2048);

            // Encrypt data
            Values encrypt(const MPI & data, const PKA::Values & pub);
            Values encrypt(const std::string & data, const PKA::Values & pub);

            // Decrypt data
            std::string decrypt(const PKA::Values & c, const PKA::Values & pri, const PKA::Values & pub);
        }
    }
}

#endif
