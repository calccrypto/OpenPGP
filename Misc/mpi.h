/*
mpi.h
Multiprecision integer (MPI) reader as defined by RFC4880 sec 3.2

Copyright (c) 2013 - 2017 Jason Lee @ calccrypto at gmail.com

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

#ifndef __MPI__
#define __MPI__

#include <cstddef>

#include <gmpxx.h>

#include "../common/includes.h"

namespace OpenPGP {
    typedef mpz_class MPI;

    MPI rawtompi(const std::string & raw);
    MPI hextompi(const std::string & hex);
    MPI dectompi(const std::string & dec);
    MPI bintompi(const std::string & bin);

    std::string mpitoraw(const MPI & a);
    std::string mpitohex(const MPI & a);
    std::string mpitodec(const MPI & a);
    std::string mpitobin(const MPI & a);

    unsigned long mpitoulong(const MPI & a);

    std::size_t bitsize(const MPI & a);

    bool knuth_prime_test(const MPI & a, int test);

    void mpiswap(MPI & a,MPI & b);
    MPI mpigcd(const MPI & a, const MPI & b);
    MPI nextprime(const MPI & a);
    MPI powm(const MPI & base, const MPI & exp, const MPI & mod);
    MPI invert(const MPI & a, const MPI & b);

    MPI random(unsigned int bits);

    std::string write_MPI(const MPI & data);                                 // given some value, return the formatted mpi
    MPI read_MPI(const std::string & data, std::string::size_type & pos);    // remove mpi from data, returning mpi value. the rest of the data will be returned through pass-by-reference

}

#endif
