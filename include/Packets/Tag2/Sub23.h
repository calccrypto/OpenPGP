/*
Sub23.h
Key Server Preferences

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

#ifndef __TAG2_SUB23__
#define __TAG2_SUB23__

#include "Packets/Tag2/Subpacket.h"

namespace OpenPGP {
    namespace Subpacket {
        namespace Tag2 {

            // 5.2.3.17. Key Server Preferences
            //
            //    (N octets of flags)
            //
            //    This is a list of one-bit flags that indicate preferences that the
            //    key holder has about how the key is handled on a key server. All
            //    undefined flags MUST be zero.
            //
            //    First octet: 0x80 = No-modify
            //        the key holder requests that this key only be modified or updated
            //        by the key holder or an administrator of the key server.
            //
            //    This is found only on a self-signature.

            namespace Key_Server_Preferences {
                constexpr uint8_t UNDEFINED = 0x00;
                constexpr uint8_t NO_MODIFY = 0x80;

                const std::map <uint8_t, std::string> NAME = {
                    std::make_pair(UNDEFINED, ""),
                    std::make_pair(NO_MODIFY, "NO-MODIFY"),
                };
            }

            class Sub23 : public Sub {
                private:
                    std::string flags;

                    void actual_read(const std::string & data);
                    void show_contents(HumanReadable & hr) const;
                    Status actual_valid(const bool check_mpi) const;

                public:
                    typedef std::shared_ptr <Sub23> Ptr;

                    Sub23();
                    Sub23(const std::string & data);
                    std::string raw() const;

                    std::string get_flags() const;

                    void set_flags(const std::string & f);

                    Sub::Ptr clone() const;
            };
        }
    }
}

#endif
