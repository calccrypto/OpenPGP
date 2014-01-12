/*
SHA512.h
The SHA2 algorithm SHA-512

Copyright (c) 2013 Jason Lee

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

#ifndef __SHA512__
#define __SHA512__

#include "../common/cryptomath.h"
#include "../common/includes.h"
#include "Hash.h"

#include "SHA2_Functions.h"
#include "SHA512_Const.h"

class SHA512 : public Hash{
    protected:
        uint64_t h0, h1, h2, h3, h4, h5, h6, h7;
        uint64_t S0(uint64_t & value);
        uint64_t S1(uint64_t & value);
        uint64_t s0(uint64_t & value);
        uint64_t s1(uint64_t & value);

        void run(const std::string & data, uint64_t & H0, uint64_t & H1, uint64_t & H2, uint64_t & H3, uint64_t & H4, uint64_t & H5, uint64_t & H6, uint64_t & H7);

    public:
        SHA512(const std::string & data = "");
        void update(const std::string & data = "");
        std::string hexdigest();
        unsigned int blocksize();
        virtual unsigned int digestsize();
};
#endif
