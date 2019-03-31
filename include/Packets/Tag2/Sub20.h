/*
Sub20.h
Notation Data

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

#ifndef __TAG2_SUB20__
#define __TAG2_SUB20__

#include "Packets/Tag2/Subpacket.h"

namespace OpenPGP {
    namespace Subpacket {
        namespace Tag2 {

            // 5.2.3.16. Notation Data
            //
            //    (4 octets of flags, 2 octets of name length (M),
            //                        2 octets of value length (N),
            //                        M octets of name data,
            //                        N octets of value data)
            //
            //    This Subpacket describes a "notation" on the signature that the
            //    issuer wishes to make. The notation has a name and a value, each of
            //    which are strings of octets. There may be more than one notation in
            //    a signature. Notations can be used for any extension the issuer of
            //    the signature cares to make. The "flags" field holds four octets of
            //    flags.
            //
            //    All undefined flags MUST be zero. Defined flags are as follows:
            //
            //        First octet: 0x80 = Human-readable. This note value is text.
            //        Other octets: none.
            //
            //    Notation names are arbitrary strings encoded in UTF-8. They reside
            //    in two namespaces: The IETF namespace and the user namespace.
            //
            //    The IETF namespace is registered with IANA. These names MUST NOT
            //    contain the "@" character (0x40). This is a tag for the user namespace.
            //
            //    Names in the user namespace consist of a UTF-8 string tag followed by
            //    "@" followed by a DNS domain name. Note that the tag MUST NOT
            //    contain an "@" character. For example, the "sample" tag used by
            //    Example Corporation could be "sample@example.com".
            //
            //    Names in a user space are owned and controlled by the owners of that
            //    domain. Obviously, it’s bad form to create a new name in a DNS space
            //    that you don’t own.
            //
            //    Since the user namespace is in the form of an email address,
            //    implementers MAY wish to arrange for that address to reach a person
            //    who can be consulted about the use of the named tag. Note that due
            //    to UTF-8 encoding, not all valid user space name tags are valid email
            //    addresses.
            //
            //    If there is a critical notation, the criticality applies to that
            //    specific notation and not to notations in general.

            namespace Notation {
                constexpr uint8_t UNDEFINED      = 0x00;
                constexpr uint8_t HUMAN_READABLE = 0x80;

                // Notation on signature issuer wishes to make
                const std::map <uint8_t, std::string> NAME = {
                    std::make_pair(UNDEFINED,      "none"),
                    std::make_pair(HUMAN_READABLE, "Human-Readable"),
                };
            }

            class Sub20 : public Sub {
                private:
                    std::string flags;  // 4 octets
                    std::string m;      // mlen octets long
                    std::string n;      // nlen octets long

                    void actual_read(const std::string & data);
                    void show_contents(HumanReadable & hr) const;
                    Status actual_valid(const bool check_mpi) const;

                public:
                    typedef std::shared_ptr <Sub20> Ptr;

                    Sub20();
                    Sub20(const std::string & data);
                    std::string raw() const;

                    std::string get_flags() const;
                    std::string get_m() const;
                    std::string get_n() const;

                    void set_flags(const std::string & f);
                    void set_m(const std::string & s);
                    void set_n(const std::string & s);

                    Sub::Ptr clone() const;
            };
        }
    }
}

#endif
