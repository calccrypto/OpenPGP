/*
mpi.h
Multiprecision integer (MPI) reader as defined by RFC4880 sec 3.2

Copyright (c) 2013, 2014 Jason Lee

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

#ifndef __PGPMPI__
#define __PGPMPI__

#include <cstddef>

#include <gmpxx.h>

#include "common/includes.h"

typedef mpz_class PGPMPI;

PGPMPI rawtompi(const std::string & raw);
PGPMPI hextompi(const std::string & hex);
PGPMPI dectompi(const std::string & dec);
PGPMPI bintompi(const std::string & bin);

std::string mpitoraw(const PGPMPI & a);
std::string mpitohex(const PGPMPI & a);
std::string mpitodec(const PGPMPI & a);
std::string mpitobin(const PGPMPI & a);

unsigned long mpitoulong(const PGPMPI & a);

unsigned int bitsize(const PGPMPI & a);

bool knuth_prime_test(const PGPMPI & a, int test);

PGPMPI mpigcd(const PGPMPI & a, const PGPMPI & b);
PGPMPI nextprime(const PGPMPI & a);
PGPMPI powm(const PGPMPI & base, const PGPMPI & exp, const PGPMPI & mod);
PGPMPI invert(const PGPMPI & a, const PGPMPI & b);

PGPMPI random(unsigned int bits);

std::string write_MPI(const PGPMPI & data);  // given some value, return the formatted mpi
PGPMPI read_MPI(std::string & data);         // remove mpi from data, returning mpi value. the rest of the data will be returned through pass-by-reference

#endif
