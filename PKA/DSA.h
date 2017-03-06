/*
DSA.h
Digital Signature Algorithm

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

#ifndef __DSA__
#define __DSA__

#include "../common/includes.h"
#include "../RNG/RNGs.h"
#include "../pgptime.h"
#include "../mpi.h"
#include "PKA.h"

// Generate new set of parameters
PKA::Values new_DSA_public(const uint32_t & L = 2048, const uint32_t & N = 256);

// Generate new keypair with parameters
PKA::Values DSA_keygen(PKA::Values & pub);

// Sign hash of data
PKA::Values DSA_sign(const PGPMPI & data, const PKA::Values & pri, const PKA::Values & pub, PGPMPI k = 0);
PKA::Values DSA_sign(const std::string & data, const PKA::Values & pri, const PKA::Values & pub, PGPMPI k = 0);

// Verify signature on hash
bool DSA_verify(const PGPMPI & data, const PKA::Values & sig, const PKA::Values & pub);
bool DSA_verify(const std::string & data, const PKA::Values & sig, const PKA::Values & pub);

#endif
