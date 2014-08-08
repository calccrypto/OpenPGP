/*
PKCS1.h
PKCS#1 as decrypted in RFC 4880 sec 13.1

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

#ifndef __PKCS1__
#define __PKCS1__

#include <iostream>
#include <stdexcept>

#include "common/includes.h"
#include "RNG/RNG.h"
#include "consts.h"
#include "mpi.h"
#include "pgptime.h"

// RFC 4880 13.1.1
std::string EME_PKCS1v1_5_ENCODE(const std::string & m, const unsigned int & k);

// RFC 4880 13.1.2
std::string EME_PKCS1v1_5_DECODE(const std::string & m);

// RFC 4880 13.1.3
std::string EMSA_PKCS1_v1_5(const uint8_t & h, const std::string & hashed_data, const unsigned int & keylength);
#endif
