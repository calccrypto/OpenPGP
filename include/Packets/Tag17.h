/*
Tag17.h
User Attribute Packet

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

#ifndef __TAG17__
#define __TAG17__

#include <vector>
#include <string>

#include "Packets/User.h"
#include "Packets/Tag17/Subpackets.h"

namespace OpenPGP {
    namespace Packet {

        // 5.12. User Attribute Packet (Tag 17)
        //
        //    The User Attribute packet is a variation of the User ID packet. It
        //    is capable of storing more types of data than the User ID packet,
        //    which is limited to text. Like the User ID packet, a User Attribute
        //    packet may be certified by the key owner ("self-signed") or any other
        //    key owner who cares to certify it. Except as noted, a User Attribute
        //    packet may be used anywhere that a User ID packet may be used.
        //
        //    While User Attribute packets are not a required part of the OpenPGP
        //    standard, implementations SHOULD provide at least enough
        //    compatibility to properly handle a certification signature on the
        //    User Attribute packet. A simple way to do this is by treating the
        //    User Attribute packet as a User ID packet with opaque contents, but
        //    an implementation may use any method desired.
        //
        //    The User Attribute packet is made up of one or more attribute
        //    subpackets. Each subpacket consists of a subpacket header and a
        //    body. The header consists of:
        //
        //      - the subpacket length (1, 2, or 5 octets)
        //
        //      - the subpacket type (1 octet)
        //
        //    and is followed by the subpacket specific data.
        //
        //    The only currently defined subpacket type is 1, signifying an image.
        //    An implementation SHOULD ignore any subpacket of a type that it does
        //    not recognize. Subpacket types 100 through 110 are reserved for
        //    private or experimental use.

        class Tag17 : public User {
            public:
                typedef std::vector <Subpacket::Tag17::Sub::Ptr> Attributes;

            private:
                // only defined subpacket is 1
                Attributes attributes;

                void read_subpacket(const std::string & data, std::string::size_type & pos, std::string::size_type & length);
                void actual_read(const std::string & data, std::string::size_type & pos, const std::string::size_type & length);
                void show_contents(HumanReadable & hr) const;
                std::string actual_raw() const;
                Status actual_valid(const bool check_mpi) const;

            public:
                typedef std::shared_ptr <Packet::Tag17> Ptr;

                Tag17();
                Tag17(const Tag17 & copy);
                Tag17(const std::string & data);
                ~Tag17();

                Attributes get_attributes() const;
                Attributes get_attributes_clone() const;
                void set_attributes(const Attributes & a);

                Tag::Ptr clone() const;
                Tag17 & operator=(const Tag17 & tag17);
        };
    }
}

#endif
