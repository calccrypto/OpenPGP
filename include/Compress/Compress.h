/*
Compress.h
List of Compression Algorithm headers

Copyright (c) 2013 - 2018 Jason Lee @ calccrypto at gmail.com

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

#ifndef __OPENPGP_COMPRESS__
#define __OPENPGP_COMPRESS__

#include <map>
#include <stdexcept>
#include <string>

// 9.3. Compression Algorithms
//
//       ID           Algorithm
//       --           ---------
//       0          - Uncompressed
//       1          - ZIP [RFC1951]
//       2          - ZLIB [RFC1950]
//       3          - BZip2 [BZ2]
//       100 to 110 - Private/Experimental algorithm
//
//    Implementations MUST implement uncompressed data. Implementations
//    SHOULD implement ZIP. Implementations MAY implement any other
//    algorithm.

#include "pgpbzip2.h"
#include "pgpzlib.h"

namespace OpenPGP {
    namespace Compression {
        namespace ID {
            const uint8_t UNCOMPRESSED          = 0;
            const uint8_t ZIP                   = 1;
            const uint8_t ZLIB                  = 2;
            const uint8_t BZIP2                 = 3;
        }

        const std::map <uint8_t, std::string> NAME = {
            std::make_pair(ID::UNCOMPRESSED,    "UNCOMPRESSED"),
            std::make_pair(ID::ZIP,             "ZIP {RFC1951}"),
            std::make_pair(ID::ZLIB,            "ZLIB {RFC1950}"),
            std::make_pair(ID::BZIP2,           "BZip2 {BZ2}"),
            std::make_pair(100,                 "Private/Experimental algorithm"),
            std::make_pair(101,                 "Private/Experimental algorithm"),
            std::make_pair(102,                 "Private/Experimental algorithm"),
            std::make_pair(103,                 "Private/Experimental algorithm"),
            std::make_pair(104,                 "Private/Experimental algorithm"),
            std::make_pair(105,                 "Private/Experimental algorithm"),
            std::make_pair(106,                 "Private/Experimental algorithm"),
            std::make_pair(107,                 "Private/Experimental algorithm"),
            std::make_pair(108,                 "Private/Experimental algorithm"),
            std::make_pair(109,                 "Private/Experimental algorithm"),
            std::make_pair(110,                 "Private/Experimental algorithm"),
        };

        const std::map <std::string, uint8_t> NUMBER = {
            std::make_pair("UNCOMPRESSED",  ID::UNCOMPRESSED),
            std::make_pair("ZIP",           ID::ZIP),
            std::make_pair("ZLIB",          ID::ZLIB),
            std::make_pair("BZip2",         ID::BZIP2),
        };

        std::string compress(const uint8_t alg, const std::string & data);
        std::string decompress(const uint8_t alg, const std::string & data);
    }
}

#endif
