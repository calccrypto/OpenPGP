/*
Sub11.h
Preferred Symmetric Algorithms

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

#ifndef __TAG2_SUB11__
#define __TAG2_SUB11__

#include "Encryptions/Encryptions.h"
#include "Packets/Tag2/Subpacket.h"

namespace OpenPGP {
    namespace Subpacket {
        namespace Tag2 {

            // 5.2.3.7. Preferred Symmetric Algorithms
            //
            //    (array of one-octet values)
            //
            //    Symmetric algorithm numbers that indicate which algorithms the key
            //    holder prefers to use. The Subpacket body is an ordered list of
            //    octets with the most preferred listed first. It is assumed that only
            //    algorithms listed are supported by the recipient’s software.
            //    Algorithm numbers are in Section 9. This is only found on a self-
            //    signature.

            class Sub11 : public Sub {
                private:
                    std::string psa;

                    void actual_read(const std::string & data);
                    Status actual_valid(const bool check_mpi) const;

                public:
                    typedef std::shared_ptr <Sub11> Ptr;

                    Sub11();
                    Sub11(const std::string & data);
                    void show_contents(HumanReadable & hr) const;
                    std::string raw() const;

                    std::string get_psa() const;  // string containing Symmetric Key Algorithm values (ex: "\x07\x08\x09")

                    void set_psa(const std::string & s);

                    Sub::Ptr clone() const;
            };
        }
    }
}

#endif
