/*
ElGamal.h
ElGamal encryption algorithm

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

#ifndef __ELGAMAL__
#define __ELGAMAL__

#include <vector>

#include "../mpi.h"

#include "../common/includes.h"
#include "../RNG/RNG.h"
#include "../pgptime.h"

std::vector <PGPMPI> ElGamal_keygen(unsigned int bits = 2048);
std::vector <PGPMPI> ElGamal_encrypt(const PGPMPI & data, const std::vector <PGPMPI> & pub);
std::vector <PGPMPI> ElGamal_encrypt(const std::string & data, const std::vector <PGPMPI> & pub);
std::string ElGamal_decrypt(std::vector <PGPMPI> & c, const std::vector <PGPMPI> & pri, const std::vector <PGPMPI> & pub);
#endif
