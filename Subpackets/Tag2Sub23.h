/*
Tag2Sub23.h
Key Server Preferences

Copyright (c) 2013 - 2017 Jason Lee @ calccrypto at gmail.com

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

#include "Tag2Subpacket.h"

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
//

namespace Key_Server_Preferences{
    typedef uint8_t type;

    const type Undefined = 0x00;
    const type No_modify = 0x80;

    const std::map <type, std::string> Name = {
        std::make_pair(Undefined, ""),
        std::make_pair(No_modify, "No-modify"),
    };
}

class Tag2Sub23 : public Tag2Subpacket{
    private:
        std::string flags;

    public:
        typedef std::shared_ptr <Tag2Sub23> Ptr;

        Tag2Sub23();
        Tag2Sub23(const std::string & data);
        void read(const std::string & data);
        std::string show(const uint8_t indents = 0, const uint8_t indent_size = 4) const;
        std::string raw() const;

        std::string get_flags() const;

        void set_flags(const std::string & f);

        Tag2Subpacket::Ptr clone() const;
};

#endif
