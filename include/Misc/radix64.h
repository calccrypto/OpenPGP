/*
radix64.h
Radix-64 converter, as defined by OpenPGP in RFC 4880 sec 6.3 and 6.4

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

#ifndef __RADIX64__
#define __RADIX64__

#include <stdexcept>
#include <string>

namespace OpenPGP {

    // 6.3.  Encoding Binary in Radix-64
    //
    //    The encoding process represents 24-bit groups of input bits as output
    //    strings of 4 encoded characters.  Proceeding from left to right, a
    //    24-bit input group is formed by concatenating three 8-bit input
    //    groups.  These 24 bits are then treated as four concatenated 6-bit
    //    groups, each of which is translated into a single digit in the
    //    Radix-64 alphabet.  When encoding a bit stream with the Radix-64
    //    encoding, the bit stream must be presumed to be ordered with the most
    //    significant bit first.  That is, the first bit in the stream will be
    //    the high-order bit in the first 8-bit octet, and the eighth bit will
    //    be the low-order bit in the first 8-bit octet, and so on.
    //
    //          +--first octet--+-second octet--+--third octet--+
    //          |7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|
    //          +-----------+---+-------+-------+---+-----------+
    //          |5 4 3 2 1 0|5 4 3 2 1 0|5 4 3 2 1 0|5 4 3 2 1 0|
    //          +--1.index--+--2.index--+--3.index--+--4.index--+
    //
    //    Each 6-bit group is used as an index into an array of 64 printable
    //    characters from the table below.  The character referenced by the
    //    index is placed in the output string.
    //
    //      Value Encoding  Value Encoding  Value Encoding  Value Encoding
    //          0 A            17 R            34 i            51 z
    //          1 B            18 S            35 j            52 0
    //          2 C            19 T            36 k            53 1
    //          3 D            20 U            37 l            54 2
    //          4 E            21 V            38 m            55 3
    //          5 F            22 W            39 n            56 4
    //          6 G            23 X            40 o            57 5
    //          7 H            24 Y            41 p            58 6
    //          8 I            25 Z            42 q            59 7
    //          9 J            26 a            43 r            60 8
    //         10 K            27 b            44 s            61 9
    //         11 L            28 c            45 t            62 +
    //         12 M            29 d            46 u            63 /
    //         13 N            30 e            47 v
    //         14 O            31 f            48 w         (pad) =
    //         15 P            32 g            49 x
    //         16 Q            33 h            50 y
    //
    //    The encoded output stream must be represented in lines of no more
    //    than 76 characters each.
    //
    //    Special processing is performed if fewer than 24 bits are available
    //    at the end of the data being encoded.  There are three possibilities:
    //
    //    1. The last data group has 24 bits (3 octets).  No special processing
    //       is needed.
    //
    //    2. The last data group has 16 bits (2 octets).  The first two 6-bit
    //       groups are processed as above.  The third (incomplete) data group
    //       has two zero-value bits added to it, and is processed as above.  A
    //       pad character (=) is added to the output.
    //
    //    3. The last data group has 8 bits (1 octet).  The first 6-bit group
    //       is processed as above.  The second (incomplete) data group has
    //       four zero-value bits added to it, and is processed as above.  Two
    //       pad characters (=) are added to the output.

    const unsigned int MAX_LINE_LENGTH = 64;

    std::string ascii2radix64(std::string str, const unsigned char char62 = '+', const unsigned char char63 = '/');

    // 6.4.  Decoding Radix-64
    //
    //    In Radix-64 data, characters other than those in the table, line
    //    breaks, and other white space probably indicate a transmission error,
    //    about which a warning message or even a message rejection might be
    //    appropriate under some circumstances.  Decoding software must ignore
    //    all white space.
    //
    //    Because it is used only for padding at the end of the data, the
    //    occurrence of any "=" characters may be taken as evidence that the
    //    end of the data has been reached (without truncation in transit).  No
    //    such assurance is possible, however, when the number of octets
    //    transmitted was a multiple of three and no "=" characters are
    //    present.

    std::string radix642ascii(std::string str, const unsigned char char62 = '+', const unsigned char char63 = '/');

}

#endif
