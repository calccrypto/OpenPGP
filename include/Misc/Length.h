/*
Length.h
Packet lengths as described in RFC 4880 sec 4.2.1 - 4.2.3 and 5.2.3.1

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

#ifndef __OPENPGP_LENGTH__
#define __OPENPGP_LENGTH__

#include <cstdint>
#include <string>

#include "Packets/Packet.h"
#include "Packets/PartialBodyLengthEnums.h"

namespace OpenPGP {

    // 4.2.1. Old Format Packet Lengths
    //
    //     0 - The packet has a one-octet length. The header is 2 octets long.
    //
    // 4.2.2.1. One-Octet Lengths
    //     A one-octet Body Length header encodes a length of 0 to 191 octets.
    //     This type of length header is recognized because the one octet value
    //     is less than 192. The body length is equal to:
    //     bodyLen = 1st_octet;
    //

    std::size_t read_one_octet_lengths(const std::string & data, std::string::size_type & pos, std::size_t &length, const Packet::HeaderFormat);

    // 4.2.1. Old Format Packet Lengths
    //
    //     1 - The packet has a two-octet length. The header is 3 octets long.
    //
    // 4.2.2.2. Two-Octet Lengths
    //
    //     A two-octet Body Length header encodes a length of 192 to 8383
    //     octets. It is recognized because its first octet is in the range 192
    //     to 223. The body length is equal to:
    //
    //         bodyLen = ((1st_octet - 192) << 8) + (2nd_octet) + 192
    //

    std::size_t read_two_octet_lengths(const std::string & data, std::string::size_type & pos, std::size_t &length, const Packet::HeaderFormat format);

    // 4.2.1. Old Format Packet Lengths
    //
    //     2 - The packet has a four-octet length. The header is 5 octets long.
    //
    // 4.2.2.3. Five-Octet Lengths
    //
    //     A five-octet Body Length header consists of a single octet holding
    //     the value 255, followed by a four-octet scalar. The body length is
    //     equal to:
    //
    //         bodyLen = (2nd_octet << 24) | (3rd_octet << 16) |
    //                   (4th_octet << 8) | 5th_octet
    //
    //     This basic set of one, two, and five-octet lengths is also used
    //     internally to some packets.
    //

    std::size_t read_five_octet_lengths(const std::string & data, std::string::size_type & pos, std::size_t &length, const Packet::HeaderFormat);

    // 4.2.1. Old Format Packet Lengths
    //
    //     3 - The packet is of indeterminate length. The header is 1 octet
    //         long, and the implementation must determine how long the packet
    //         is. If the packet is in a file, this means that the packet
    //         extends until the end of the file. In general, an implementation
    //         SHOULD NOT use indeterminate-length packets except where the end
    //         of the data will be clear from the context, and even then it is
    //         better to use a definite length, or a new format header. The new
    //         format headers described below have a mechanism for precisely
    //         encoding data of indeterminate length.
    //
    // 4.2.2.4. Partial Body Lengths
    //
    //     A Partial Body Length header is one octet long and encodes the length
    //     of only part of the data packet. This length is a power of 2, from 1
    //     to 1,073,741,824 (2 to the 30th power). It is recognized by its one
    //     octet value that is greater than or equal to 224, and less than 255.
    //     The Partial Body Length is equal to:
    //
    //         partialBodyLen = 1 << (1st_octet & 0x1F);
    //
    //     Each Partial Body Length header is followed by a portion of the
    //     packet body data. The Partial Body Length header specifies this
    //     portion’s length. Another length header (one octet, two-octet,
    //     five-octet, or partial) follows that portion. The last length header
    //     in the packet MUST NOT be a Partial Body Length header. Partial Body
    //     Length headers may only be used for the non-final parts of the
    //     packet.
    //
    //     Note also that the last Body Length header can be a zero-length
    //     header.
    //
    //     An implementation MAY use Partial Body Lengths for data packets, be
    //     they literal, compressed, or encrypted. The first partial length
    //     MUST be at least 512 octets long. Partial Body Lengths MUST NOT be
    //     used for any other packet types.
    //

    std::size_t read_partialBodyLen(uint8_t first_octet, const Packet::HeaderFormat);

    // returns Tag data with old format Tag length
    // octets trys to force the data into an octet length type; mostly useful for writing into larger octet lengths
    std::string write_old_length(const uint8_t tag, const std::string & data, const Packet::PartialBodyLength part, uint8_t octets = 0);

    // returns Tag data with new format Tag length
    // octets trys to force the data into an octet length type; mostly useful for writing into larger octet lengths
    std::string write_new_length(const uint8_t tag, const std::string & data, const Packet::PartialBodyLength part, uint8_t octets = 0);
}

#endif
