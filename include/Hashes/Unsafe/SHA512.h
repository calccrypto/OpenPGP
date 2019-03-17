/*
SHA512.h
The SHA2 algorithm SHA-512

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

#ifndef __SHA512__
#define __SHA512__

#include "common/cryptomath.h"
#include "common/includes.h"
#include "Hashes/MerkleDamgard.h"

#include "SHA2_Functions.h"
#include "SHA512_Const.h"

namespace OpenPGP {
    namespace Hash {
        class SHA512 : public MerkleDamgard {
            protected:
                struct context{
                    uint64_t h0, h1, h2, h3, h4, h5, h6, h7;
                    ~context(){
                        h0 = h1 = h2 = h3 = h4 = h5 = h6 = h7 = 0;
                    }
                };
                context ctx;

                uint64_t S0(uint64_t & value) const;
                uint64_t S1(uint64_t & value) const;
                uint64_t s0(uint64_t & value) const;
                uint64_t s1(uint64_t & value) const;

                virtual void original_h();

                void calc(const std::string & data, context & state) const;

            public:
                SHA512();
                SHA512(const std::string & data);
                void update(const std::string & str);
                virtual std::string hexdigest();
                virtual std::size_t blocksize() const;
                virtual std::size_t digestsize() const;
        };
    }
}

#endif
