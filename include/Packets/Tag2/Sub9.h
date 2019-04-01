/*
Sub9.h
Key Expiration Time

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

#ifndef __TAG2_SUB9__
#define __TAG2_SUB9__

#include "Packets/Tag2/Subpacket.h"

namespace OpenPGP {
    namespace Subpacket {
        namespace Tag2 {

            // 5.2.3.6. Key Expiration Time
            //
            //    (4-octet time field)
            //
            //    The validity period of the key. This is the number of seconds after
            //    the key creation time that the key expires. If this is not present
            //    or has a value of zero, the key never expires. This is found only on
            //    a self-signature.

            class Sub9 : public Sub {
                private:
                    uint32_t dt;

                    void actual_read(const std::string & data);
                    void show_contents(HumanReadable & hr) const;
                    Status actual_valid(const bool check_mpi) const;

                public:
                    typedef std::shared_ptr <Sub9> Ptr;

                    Sub9();
                    Sub9(const std::string & data);
                    std::string raw() const;
                    using Sub::show;
                    void show(const uint32_t create_time, HumanReadable & hr) const;
                    uint32_t get_dt() const;

                    void set_dt(const uint32_t t);

                    Sub::Ptr clone() const;
            };
        }
    }
}

#endif
