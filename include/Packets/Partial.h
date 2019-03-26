/*
Partial.h
Special class for OpenPGP packet types that can have partial body lengths to inherit from

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

#ifndef __PARTIAL__
#define __PARTIAL__

#include <cstdint>
#include <memory>
#include <string>

#include "Packets/Packet.h"
#include "Packets/PartialBodyLengthEnums.h"

namespace OpenPGP {
    namespace Packet {

        // 4.2.1.  Old Format Packet Lengths
        //
        //     The meaning of the length-type in old format packets is:
        //
        //     ...
        //
        //
        //     3 - The packet is of indeterminate length.  The header is 1 octet
        //         long, and the implementation must determine how long the packet
        //         is.  If the packet is in a file, this means that the packet
        //         extends until the end of the file.  In general, an implementation
        //         SHOULD NOT use indeterminate-length packets except where the end
        //         of the data will be clear from the context, and even then it is
        //         better to use a definite length, or a new format header.  The new
        //         format headers described below have a mechanism for precisely
        //         encoding data of indeterminate length.

        // 4.2.2.4.  Partial Body Lengths
        //
        //     A Partial Body Length header is one octet long and encodes the length
        //     of only part of the data packet.  This length is a power of 2, from 1
        //     to 1,073,741,824 (2 to the 30th power).  It is recognized by its one
        //     octet value that is greater than or equal to 224, and less than 255.
        //     The Partial Body Length is equal to:
        //
        //         partialBodyLen = 1 << (1st_octet & 0x1F);
        //
        //     Each Partial Body Length header is followed by a portion of the
        //     packet body data.  The Partial Body Length header specifies this
        //     portion's length.  Another length header (one octet, two-octet,
        //     five-octet, or partial) follows that portion.  The last length header
        //     in the packet MUST NOT be a Partial Body Length header.  Partial Body
        //     Length headers may only be used for the non-final parts of the
        //     packet.
        //
        //     Note also that the last Body Length header can be a zero-length
        //     header.
        //
        //     An implementation MAY use Partial Body Lengths for data packets, be
        //     they literal, compressed, or encrypted.  The first partial length
        //     MUST be at least 512 octets long.  Partial Body Lengths MUST NOT be
        //     used for any other packet types.

        static const uint8_t PARTIAL_BODY_LENGTH_START = 224;
        static const uint8_t PARTIAL_BODY_LENGTH_END   = 254;

        class Partial {
            protected:
                PartialBodyLength partial;  // whether or not this packet has a partial body length

                std::string show_title() const;
                std::string write(const HeaderFormat & header_format, const uint8_t tag, const std::string & data) const;

            public:
                typedef std::shared_ptr <Partial> Ptr;

                Partial(const PartialBodyLength &part = NOT_PARTIAL);
                Partial(const Partial &copy);
                virtual ~Partial();

                PartialBodyLength get_partial() const;

                void set_partial(const PartialBodyLength & part);

                static bool can_have_partial_length(const uint8_t tag);       // check if a packet type can have partial body lengths
                static bool can_have_partial_length(const Tag::Ptr & packet); // check if a packet can have partial body lengths

                Partial & operator=(const Partial &copy);
        };
    }
}

#endif
