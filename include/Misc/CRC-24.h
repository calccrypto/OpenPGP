/*
CRC-24.h
CRC-24, as defined by OpenPGP in RFC 4880 sec 6.1

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

#ifndef __CRC24__
#define __CRC24__

#include <cstdint>
#include <string>

namespace OpenPGP {
    // 6.1.  An Implementation of the CRC-24 in "C"
    //
    //       #define CRC24_INIT 0xB704CEL
    //       #define CRC24_POLY 0x1864CFBL
    //
    //       typedef long crc24;
    //       crc24 crc_octets(unsigned char *octets, size_t len)
    //       {
    //           crc24 crc = CRC24_INIT;
    //           int i;
    //           while (len--) {
    //               crc ^= (*octets++) << 16;
    //               for (i = 0; i < 8; i++) {
    //                   crc <<= 1;
    //                   if (crc & 0x1000000)
    //                       crc ^= CRC24_POLY;
    //               }
    //           }
    //           return crc & 0xFFFFFFL;
    //       }
    uint32_t crc24(const std::string & str);
}

#endif