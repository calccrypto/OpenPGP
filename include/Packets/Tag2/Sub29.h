/*
Sub29.h
Reason for Revocation

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

#ifndef __TAG2_SUB29__
#define __TAG2_SUB29__

#include "Packets/Tag2/Subpacket.h"

namespace OpenPGP {
    namespace Subpacket {
        namespace Tag2 {
            namespace Revoke {
                constexpr uint8_t NO_REASON_SPECIFIED                      = 0;
                constexpr uint8_t KEY_IS_SUPERCEEDED                       = 1;
                constexpr uint8_t KEY_MATERIAL_HAS_BEEN_COMPROMISED        = 2;
                constexpr uint8_t KEY_IS_NO_LONGER_USED                    = 3;
                constexpr uint8_t USER_ID_INFORMATION_IS_NO_LONGER_VALID   = 32;

                const std::map <uint8_t, std::string> NAME = {
                    std::make_pair(NO_REASON_SPECIFIED,                    "No reason specified"),
                    std::make_pair(KEY_IS_SUPERCEEDED,                     "Key is superceded"),
                    std::make_pair(KEY_MATERIAL_HAS_BEEN_COMPROMISED,      "Key material has been compromised"),
                    std::make_pair(KEY_IS_NO_LONGER_USED,                  "Key is no longer used"),
                    std::make_pair(USER_ID_INFORMATION_IS_NO_LONGER_VALID, "User ID information is no longer valid"),
                    std::make_pair(100,                                    "Private Use"),
                    std::make_pair(101,                                    "Private Use"),
                    std::make_pair(102,                                    "Private Use"),
                    std::make_pair(103,                                    "Private Use"),
                    std::make_pair(104,                                    "Private Use"),
                    std::make_pair(105,                                    "Private Use"),
                    std::make_pair(106,                                    "Private Use"),
                    std::make_pair(107,                                    "Private Use"),
                    std::make_pair(108,                                    "Private Use"),
                    std::make_pair(109,                                    "Private Use"),
                    std::make_pair(110,                                    "Private Use"),
                };

                bool is_key_revocation(const uint8_t code);
            }

            // 5.2.3.23.  Reason for Revocation
            //
            //    (1 octet of revocation code, N octets of reason string)
            //
            //    This Subpacket is used only in key revocation and certification
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
            //    information about the Reason for Revocation in Human-readable form
            //    (UTF-8).  The string may be null, that is, of zero length.  The
            //    length of the Subpacket is the length of the reason string plus one.
            //    An implementation SHOULD implement this Subpacket, include it in all
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

            class Sub29 : public Sub {
                private:
                    uint8_t code;
                    std::string reason;

                    void actual_read(const std::string & data);
                    void show_contents(HumanReadable & hr) const;
                    Status actual_valid(const bool check_mpi) const;

                public:
                    typedef std::shared_ptr <Sub29> Ptr;

                    Sub29();
                    Sub29(const std::string & data);
                    std::string raw() const;

                    uint8_t get_code() const;
                    std::string get_reason() const;

                    void set_code(const uint8_t c);
                    void set_reason(const std::string & r);

                    Sub::Ptr clone() const;
            };
        }
    }
}

#endif
