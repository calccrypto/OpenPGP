/*
MD5.h
MD5 hashing algorithm

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

#ifndef __MD5__
#define __MD5__

#include "common/cryptomath.h"
#include "common/includes.h"
#include "Hashes/MerkleDamgard.h"

#include "MD5_Const.h"

namespace OpenPGP {
    namespace Hash {
        class MD5 : public MerkleDamgard {
            private:
                struct context{
                    uint32_t h0, h1, h2, h3;
                    context(uint32_t h0, uint32_t h1, uint32_t h2, uint32_t h3) :
                        h0(h0),
                        h1(h1),
                        h2(h2),
                        h3(h3)
                    {}
                    ~context(){
                        h0 = h1 = h2 = h3 = 0;
                    }
                };
                context ctx;

                std::string to_little_end(const std::string & data) const;
                void calc(const std::string & data, context & state) const;

            public:
                MD5();
                MD5(const std::string & data);
                void update(const std::string & data);
                std::string hexdigest();
                std::size_t blocksize() const;
                std::size_t digestsize() const;
        };
    }
}

#endif
