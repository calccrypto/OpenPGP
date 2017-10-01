/*
Tag8.h
Compressed Data Packet

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

#ifndef __TAG8__
#define __TAG8__

#include "../Compress/Compress.h"
#include "Packet.h"

namespace OpenPGP {
    namespace Packet {

        // 5.6.  Compressed Data Packet (Tag 8)
        //
        //    The Compressed Data packet contains compressed data.  Typically, this
        //    packet is found as the contents of an encrypted packet, or following
        //    a Signature or One-Pass Signature packet, and contains a literal data
        //    packet.
        //
        //    The body of this packet consists of:
        //
        //      - One octet that gives the algorithm used to compress the packet.
        //
        //      - Compressed data, which makes up the remainder of the packet.
        //
        //    A Compressed Data Packet's body contains an block that compresses
        //    some set of packets.  See section "Packet Composition" for details on
        //    how messages are formed.
        //
        //    ZIP-compressed packets are compressed with raw RFC 1951 [RFC1951]
        //    DEFLATE blocks.  Note that PGP V2.6 uses 13 bits of compression.  If
        //    an implementation uses more bits of compression, PGP V2.6 cannot
        //    decompress it.
        //
        //    ZLIB-compressed packets are compressed with RFC 1950 [RFC1950] ZLIB-
        //    style blocks.
        //
        //    BZip2-compressed packets are compressed using the BZip2 [BZ2]
        //    algorithm.

        class Tag8 : public Tag {
            private:
                uint8_t comp;
                std::string compressed_data;

                // call external functions to do compression and decompression
                std::string compress(const std::string & data) const;
                std::string decompress(const std::string & data) const;

                std::string show_title() const;

            public:
                typedef std::shared_ptr <Packet::Tag8> Ptr;

                Tag8();
                Tag8(const Tag8 & copy);
                Tag8(const std::string & data);
                void read(const std::string & data);
                std::string show(const std::size_t indents = 0, const std::size_t indent_size = 4) const;
                std::string raw() const;

                uint8_t get_comp() const;
                std::string get_data() const;                           // get uncompressed data
                std::string get_compressed_data() const;                // get compressed data

                void set_comp(const uint8_t alg);
                void set_data(const std::string & data);                // set uncompressed data
                void set_compressed_data(const std::string & data);     // set compressed data

                Tag::Ptr clone() const;
        };
    }
}

#endif
