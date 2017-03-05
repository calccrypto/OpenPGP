/*
Tag2Sub27.h
Key Flags

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

#ifndef __TAG2_SUB27__
#define __TAG2_SUB27__

#include "Tag2Subpacket.h"

// 5.2.3.21.  Key Flags
//
//    (N octets of flags)
//
//    This subpacket contains a list of binary flags that hold information
//    about a key.  It is a string of octets, and an implementation MUST
//    NOT assume a fixed size.  This is so it can grow over time.  If a
//    list is shorter than an implementation expects, the unstated flags
//    are considered to be zero.  The defined flags are as follows:
//
//        First octet:
//
//        0x01 - This key may be used to certify other keys.
//
//        0x02 - This key may be used to sign data.
//
//        0x04 - This key may be used to encrypt communications.
//
//        0x08 - This key may be used to encrypt storage.
//
//        0x10 - The private component of this key may have been split
//               by a secret-sharing mechanism.
//
//        0x20 - This key may be used for authentication.
//
//        0x80 - The private component of this key may be in the
//               possession of more than one person.
//
//    Usage notes:
//
//    The flags in this packet may appear in self-signatures or in
//    certification signatures.  They mean different things depending on
//    who is making the statement -- for example, a certification signature
//    that has the "sign data" flag is stating that the certification is
//    for that use.  On the other hand, the "communications encryption"
//    flag in a self-signature is stating a preference that a given key be
//    used for communications.  Note however, that it is a thorny issue to
//    determine what is "communications" and what is "storage".  This
//    decision is left wholly up to the implementation; the authors of this
//    document do not claim any special wisdom on the issue and realize
//    that accepted opinion may change.
//
//    The "split key" (0x10) and "group key" (0x80) flags are placed on a
//    self-signature only; they are meaningless on a certification
//    signature.  They SHOULD be placed only on a direct-key signature
//    (type 0x1F) or a subkey signature (type 0x18), one that refers to the
//    key the flag applies to.
//

namespace Key_Flags{
    typedef uint8_t type;

    const type Certify_Other_Keys                   = 0x01;
    const type Sign_Data                            = 0x02;
    const type Encrypt_Communications               = 0x04;
    const type Encrypt_Storage                      = 0x08;
    const type Private_Component_Split              = 0x10;
    const type Authentication                       = 0x20;
    const type Private_Component_Multiple_Posession = 0x80;

    const std::map <type, std::string> Name = {
        std::make_pair(Certify_Other_Keys,                   "This key may be used to certify other keys"),
        std::make_pair(Sign_Data,                            "This key may be used to sign data"),
        std::make_pair(Encrypt_Communications,               "This key may be used to encrypt communications"),
        std::make_pair(Encrypt_Storage,                      "This key may be used to encrypt storage"),
        std::make_pair(Private_Component_Split,              "The private component of this key may have been split by a secret-sharing mechanism"),
        std::make_pair(Authentication,                       "This key may be used for authentication"),
        std::make_pair(Private_Component_Multiple_Posession, "The private component of this key may be in the possession of more than one person"),
    };
}

class Tag2Sub27 : public Tag2Subpacket{
    private:
        std::string flags;

    public:
        typedef std::shared_ptr <Tag2Sub27> Ptr;

        Tag2Sub27();
        Tag2Sub27(const std::string & data);
        void read(const std::string & data);
        std::string show(const uint8_t indents = 0, const uint8_t indent_size = 4) const;
        std::string raw() const;

        std::string get_flags() const;

        void set_flags(const std::string & f);

        Tag2Subpacket::Ptr clone() const;
};

#endif
