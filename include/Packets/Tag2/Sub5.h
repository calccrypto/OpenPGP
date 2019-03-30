/*
Sub5.h
Trust Signature

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

#ifndef __TAG2_SUB5__
#define __TAG2_SUB5__

#include "Packets/Tag2/Subpacket.h"

namespace OpenPGP {
    namespace Subpacket {
        namespace Tag2 {

            // 5.2.3.13. Trust Signature
            //
            //    (1 octet "level" (depth), 1 octet of trust amount)
            //
            //    Signer asserts that the key is not only valid but also trustworthy at
            //    the specified level. Level 0 has the same meaning as an ordinary
            //    validity signature. Level 1 means that the signed key is asserted to
            //    be a valid trusted introducer, with the 2nd octet of the body
            //    specifying the degree of trust. Level 2 means that the signed key is
            //    asserted to be trusted to issue level 1 trust signatures, i.e., that
            //    it is a "meta introducer". Generally, a level n trust signature
            //    asserts that a key is trusted to issue level n-1 trust signatures.
            //    The trust amount is in a range from 0-255, interpreted such that
            //    values less than 120 indicate partial trust and values of 120 or
            //    greater indicate complete trust. Implementations SHOULD emit values
            //    of 60 for partial trust and 120 for complete trust.

            class Sub5 : public Sub {
                private:
                    uint8_t level;
                    uint8_t amount;

                    void actual_read(const std::string & data);
                    void show_contents(HumanReadable & hr) const;
                    Status actual_valid(const bool check_mpi) const;

                public:
                    typedef std::shared_ptr <Sub5> Ptr;

                    Sub5();
                    Sub5(const std::string & data);
                    std::string raw() const;

                    uint8_t get_level() const;
                    uint8_t get_amount() const;

                    void set_level(const uint8_t l);
                    void set_amount(const uint8_t a);

                    Sub::Ptr clone() const;
            };
        }
    }
}

#endif
