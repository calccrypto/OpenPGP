/*
Tag19.h
Modification Detection Code Packet

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

#ifndef __TAG19__
#define __TAG19__

#include "Hashes/Hashes.h"
#include "Packets/Packet.h"

namespace OpenPGP {
    namespace Packet {

        // 5.14. Modification Detection Code Packet (Tag 19)
        //
        //    The Modification Detection Code packet contains a SHA-1 hash of
        //    plaintext data, which is used to detect message modification. It is
        //    only used with a Symmetrically Encrypted Integrity Protected Data
        //    packet. The Modification Detection Code packet MUST be the last
        //    packet in the plaintext data that is encrypted in the Symmetrically
        //    Encrypted Integrity Protected Data packet, and MUST appear in no
        //    other place.
        //
        //    A Modification Detection Code packet MUST have a length of 20 octets.
        //    The body of this packet consists of:
        //
        //      - A 20-octet SHA-1 hash of the preceding plaintext data of the
        //        Symmetrically Encrypted Integrity Protected Data packet,
        //        including prefix data, the tag octet, and length octet of the
        //        Modification Detection Code packet.
        //
        //    Note that the Modification Detection Code packet MUST always use a
        //    new format encoding of the packet tag, and a one-octet encoding of
        //    the packet length. The reason for this is that the hashing rules for
        //    modification detection include a one-octet tag and one-octet length
        //    in the data hash. While this is a bit restrictive, it reduces
        //    complexity.

        class Tag19 : public Tag {
            private:
                std::string hash;

                void actual_read(const std::string & data, std::string::size_type & pos, const std::string::size_type & length);
                void show_contents(HumanReadable & hr) const;
                std::string actual_raw() const;
                Status actual_valid(const bool check_mpi) const;

            public:
                typedef std::shared_ptr <Packet::Tag19> Ptr;

                Tag19();
                Tag19(const std::string & data);

                std::string get_hash() const;

                void set_hash(const std::string & h);

                Tag::Ptr clone() const;
        };
    }
}

#endif
