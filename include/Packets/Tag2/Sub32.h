/*
Sub32.h
Embedded Signature

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

#ifndef __TAG2_SUB32__
#define __TAG2_SUB32__

#include "Packets/Tag2.h"
#include "Packets/Tag2/Subpacket.h"

namespace OpenPGP {
    namespace Subpacket {
        namespace Tag2 {

            // 5.2.3.26.  Embedded Signature
            //
            //    (1 signature packet body)
            //
            //    This Subpacket contains a complete Signature packet body as
            //    specified in Section 5.2 above.  It is useful when one signature
            //    needs to refer to, or be incorporated in, another signature.

            class Sub32 : public Sub {
                private:
                    Packet::Tag2::Ptr embedded;

                    void actual_read(const std::string & data);
                    void show_contents(HumanReadable & hr) const;
                    Status actual_valid(const bool check_mpi) const;

                public:
                    typedef std::shared_ptr <Sub32> Ptr;

                    Sub32();
                    Sub32(const Sub32 & Sub32);
                    Sub32(const std::string & data);
                    ~Sub32();
                    std::string raw() const;

                    Packet::Tag2::Tag::Ptr get_embedded() const;

                    void set_embedded(const Packet::Tag2::Ptr & e, const bool copy = false);

                    Sub::Ptr clone() const;
                    Sub32 & operator=(const Sub32 & copy);
            };
        }
    }
}

#endif
