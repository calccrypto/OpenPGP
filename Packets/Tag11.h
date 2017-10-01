/*
Tag11.h
Literal Data Packet

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

#ifndef __TAG11__
#define __TAG11__

#include <fstream>
#include <sstream>

#include "../Misc/pgptime.h"
#include "Packet.h"

namespace OpenPGP {
    namespace Packet {

        // 5.9. Literal Data Packet (Tag 11)
        //
        //    A Literal Data packet contains the body of a message; data that is
        //    not to be further interpreted.
        //
        //    The body of this packet consists of:
        //
        //      - A one-octet field that describes how the data is formatted.
        //
        //    If it is a ’b’ (0x62), then the Literal packet contains binary data.
        //    If it is a ’t’ (0x74), then it contains text data, and thus may need
        //    line ends converted to local form, or other text-mode changes. The
        //    tag ’u’ (0x75) means the same as ’t’, but also indicates that
        //    implementation believes that the literal data contains UTF-8 text.
        //
        //    Early versions of PGP also defined a value of ’l’ as a ’local’ mode
        //    for machine-local conversions. RFC 1991 [RFC1991] incorrectly stated
        //    this local mode flag as ’1’ (ASCII numeral one). Both of these local
        //    modes are deprecated.
        //
        //      - File name as a string (one-octet length, followed by a file
        //        name). This may be a zero-length string. Commonly, if the
        //        source of the encrypted data is a file, this will be the name of
        //        the encrypted file. An implementation MAY consider the file name
        //        in the Literal packet to be a more authoritative name than the
        //        actual file name.
        //
        //    If the special name "_CONSOLE" is used, the message is considered to
        //    be "for your eyes only". This advises that the message data is
        //    unusually sensitive, and the receiving program should process it more
        //    carefully, perhaps avoiding storing the received data to disk, for
        //    example.
        //
        //      - A four-octet number that indicates a date associated with the
        //        literal data. Commonly, the date might be the modification date
        //        of a file, or the time the packet was created, or a zero that
        //        indicates no specific time.
        //
        //      - The remainder of the packet is literal data.
        //
        //    Text data is stored with <CR><LF> text endings (i.e., network-
        //    normal line endings). These should be converted to native line
        //    endings by the receiving software.

        namespace Literal {
            const uint8_t BINARY    = 'b';     // should be equal to 0x62
            const uint8_t TEXT      = 't';     // should be equal to 0x74
            const uint8_t UTF8_TEXT = 'u';     // should be equal to 0x75

            const std::map <uint8_t, std::string> NAME = {
                std::make_pair(BINARY,    "Binary"),
                std::make_pair(TEXT,      "Text"),
                std::make_pair(UTF8_TEXT, "UTF-8 Text"),
            };
        }

        class Tag11 : public Tag {
            private:
                uint8_t format;
                std::string filename;
                uint32_t time;
                std::string literal;    // source data; no line ending conversion

            public:
                typedef std::shared_ptr <Packet::Tag11> Ptr;

                Tag11();
                Tag11(const Tag11 & copy);
                Tag11(const std::string & data);
                void read(const std::string & data);
                std::string show(const std::size_t indents = 0, const std::size_t indent_size = 4) const;
                std::string raw() const;

                uint8_t get_format() const;
                std::string get_filename() const;
                uint32_t get_time() const;
                std::string get_literal() const;
                std::string out(const bool writefile = true); // send data to

                void set_format(const uint8_t f);
                void set_filename(const std::string & f);
                void set_time(const uint32_t t);
                void set_literal(const std::string & l);

                Tag::Ptr clone() const;
        };
    }
}

#endif
