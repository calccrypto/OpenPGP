/*
Tag2Sub29.h
Reason for Revocation

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

#ifndef __TAG2_SUB29__
#define __TAG2_SUB29__

#include "Tag2Subpacket.h"

// 5.2.3.23.  Reason for Revocation
//
//    (1 octet of revocation code, N octets of reason string)
//
//    This subpacket is used only in key revocation and certification
//    revocation signatures.  It describes the reason why the key or
//    certificate was revoked.
//
//    The first octet contains a machine-readable code that denotes the
//    reason for the revocation:
//
//         0  - No reason specified (key revocations or cert revocations)
//         1  - Key is superseded (key revocations)
//         2  - Key material has been compromised (key revocations)
//         3  - Key is retired and no longer used (key revocations)
//         32 - User ID information is no longer valid (cert revocations)
//    100-110 - Private Use
//
//    Following the revocation code is a string of octets that gives
//    information about the Reason for Revocation in human-readable form
//    (UTF-8).  The string may be null, that is, of zero length.  The
//    length of the subpacket is the length of the reason string plus one.
//    An implementation SHOULD implement this subpacket, include it in all
//    revocation signatures, and interpret revocations appropriately.
//    There are important semantic differences between the reasons, and
//    there are thus important reasons for revoking signatures.
//
//    If a key has been revoked because of a compromise, all signatures
//    created by that key are suspect.  However, if it was merely
//    superseded or retired, old signatures are still valid.  If the
//    revoked signature is the self-signature for certifying a User ID, a
//    revocation denotes that that user name is no longer in use.  Such a
//    revocation SHOULD include a 0x20 code.
//
//    Note that any signature may be revoked, including a certification on
//    some other person's key.  There are many good reasons for revoking a
//    certification signature, such as the case where the keyholder leaves
//    the employ of a business with an email address.  A revoked
//    certification is no longer a part of validity calculations.
//

namespace Revoke{
    typedef uint8_t type;
    const type No_reason_specified                    = 0;
    const type Key_is_superceeded                     = 1;
    const type Key_material_has_been_compromised      = 2;
    const type Key_is_no_longer_used                  = 3;
    const type User_ID_information_is_no_longer_valid = 32;

    const std::map <type, std::string> Name = {
        std::make_pair(No_reason_specified,                    "No reason specified"),
        std::make_pair(Key_is_superceeded,                     "Key is superceded"),
        std::make_pair(Key_material_has_been_compromised,      "Key material has been compromised"),
        std::make_pair(Key_is_no_longer_used,                  "Key is no longer used"),
        std::make_pair(User_ID_information_is_no_longer_valid, "User ID information is no longer valid"),
    };
}

class Tag2Sub29 : public Tag2Subpacket{
    private:
        Revoke::type code;
        std::string reason;

    public:
        typedef std::shared_ptr <Tag2Sub29> Ptr;

        Tag2Sub29();
        Tag2Sub29(const std::string & data);
        void read(const std::string & data);
        std::string show(const uint8_t indents = 0, const uint8_t indent_size = 4) const;
        std::string raw() const;

        Revoke::type get_code() const;
        std::string get_reason() const;

        void set_code(const Revoke::type c);
        void set_reason(const std::string & r);

        Tag2Subpacket::Ptr clone() const;
};

#endif
