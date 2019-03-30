/*
Tag10.h
Marker Packet

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

#ifndef __TAG10__
#define __TAG10__

#include "Packets/Packet.h"

namespace OpenPGP {
    namespace Packet {

        // 5.8.  Marker Packet (Obsolete Literal Packet) (Tag 10)
        //
        //    An experimental version of PGP used this packet as the Literal
        //    packet, but no released version of PGP generated Literal packets with
        //    this tag.  With PGP 5.x, this packet has been reassigned and is
        //    reserved for use as the Marker packet.
        //
        //    The body of this packet consists of:
        //
        //      - The three octets 0x50, 0x47, 0x50 (which spell "PGP" in UTF-8).
        //
        //    Such a packet MUST be ignored when received.  It may be placed at the
        //    beginning of a message that uses features not available in PGP 2.6.x
        //    in order to cause that version to report that newer software is
        //    necessary to process the message.

        class Tag10 : public Tag {
            public:
                static const std::string body; // "PGP"

            private:
                std::string pgp; // should always be "PGP"

                void actual_read(const std::string & data, std::string::size_type & pos, const std::string::size_type & length);
                void show_contents(HumanReadable & hr) const;
                std::string actual_raw() const;
                Status actual_valid(const bool check_mpi) const;

            public:
                typedef std::shared_ptr <Packet::Tag10> Ptr;

                Tag10();
                Tag10(const Tag10 & copy);
                Tag10(const std::string & data);

                std::string get_pgp() const;

                void set_pgp(const std::string & s = body);

                Tag::Ptr clone() const;
        };
    }
}

#endif
