/*
Sub21.h
Preferred Hash Algorithms

Copyright (c) 2013 - 2018 Jason Lee @ calccrypto at gmail.com

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

#ifndef __TAG2_SUB21__
#define __TAG2_SUB21__

#include "../../Hashes/Hashes.h"
#include "Subpacket.h"

namespace OpenPGP {
    namespace Subpacket {
        namespace Tag2 {
            // 5.2.3.8. Preferred Hash Algorithms
            //
            //    (array of one-octet values)
            //
            //    Message digest algorithm numbers that indicate which algorithms the
            //    key holder prefers to receive. Like the preferred symmetric
            //    algorithms, the list is ordered. Algorithm numbers are in Section 9.
            //    This is only found on a self-signature.

            class Sub21 : public Sub {
                private:
                    std::string pha;

                public:
                    typedef std::shared_ptr <Sub21> Ptr;

                    Sub21();
                    Sub21(const std::string & data);
                    void read(const std::string & data);
                    std::string show(const std::size_t indents = 0, const std::size_t indent_size = 4) const;
                    std::string raw() const;

                    std::string get_pha() const;  // returns string of preferred hash algorithms (ex: "\x01\x02\x03")

                    void set_pha(const std::string & p);

                    Sub::Ptr clone() const;
            };
        }
    }
}

#endif
