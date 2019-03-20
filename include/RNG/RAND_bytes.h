/*
RAND_bytes.h
A wrapper around OpenSSL's RAND_bytes function

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

#ifndef __RAND_BYTES__
#define __RAND_BYTES__

#include <string>

#include <openssl/rand.h>

namespace OpenPGP {
    namespace RNG {
        class RAND_bytes{
            static bool seeded;

            static void seed(const void * buf, int num);

            public:
                RAND_bytes(...);
                RAND_bytes(const std::string & seed);
                RAND_bytes(const void * buf, int num);
                std::string rand_bits (const unsigned int & bits  = 1, const std::size_t max_attempts = 5);
                std::string rand_bytes(const unsigned int & bytes = 1, const std::size_t max_attempts = 5);
        };
    }
}

#endif
