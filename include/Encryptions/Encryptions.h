/*
Encryptions.h

The MIT License (MIT)

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

#ifndef ENCRYPTIONS_H
#define ENCRYPTIONS_H

#include <map>
#include <stdexcept>
#include <string>

#include "SymAlg.h"

#include "AES.h"
#include "Blowfish.h"
#include "CAST128.h"
#include "Camellia.h"
#include "DES.h"
#include "IDEA.h"
#include "TDES.h"
#include "Twofish.h"

namespace OpenPGP {
    namespace Sym {
        // 9.2.  Symmetric-Key Algorithms
        //
        //        ID           Algorithm
        //        --           ---------
        //        0          - Plaintext or unencrypted data
        //        1          - IDEA [IDEA]
        //        2          - TripleDES (DES-EDE, [SCHNEIER] [HAC] -
        //                     168 bit key derived from 192)
        //        3          - CAST5 (128 bit key, as per [RFC2144])
        //        4          - Blowfish (128 bit key, 16 rounds) [BLOWFISH]
        //        5          - Reserved
        //        6          - Reserved
        //        7          - AES with 128-bit key [AES]
        //        8          - AES with 192-bit key
        //        9          - AES with 256-bit key
        //        10         - Twofish with 256-bit key [TWOFISH]
        //        100 to 110 - Private/Experimental algorithm
        //
        //    PGP 2.6 or earlier need to support IDEA, as that is the only
        //    symmetric cipher those versions use.  Implementations MAY implement
        //    any other algorithm.
        //

        namespace ID {
            constexpr uint8_t PLAINTEXT     = 0;
            constexpr uint8_t IDEA          = 1;
            constexpr uint8_t TRIPLEDES     = 2;
            constexpr uint8_t CAST5         = 3;
            constexpr uint8_t BLOWFISH      = 4;
            constexpr uint8_t AES128        = 7;
            constexpr uint8_t AES192        = 8;
            constexpr uint8_t AES256        = 9;
            constexpr uint8_t TWOFISH256    = 10;
            constexpr uint8_t CAMELLIA128   = 11;
            constexpr uint8_t CAMELLIA192   = 12;
            constexpr uint8_t CAMELLIA256   = 13;
        }

        const std::map <uint8_t, std::string> NAME = {
            std::make_pair(ID::PLAINTEXT,   "PLAINTEXT"),
            std::make_pair(ID::IDEA,        "IDEA"),
            std::make_pair(ID::TRIPLEDES,   "TRIPLEDES"),
            std::make_pair(ID::CAST5,       "CAST5"),
            std::make_pair(ID::BLOWFISH,    "BLOWFISH"),
            std::make_pair(5,               "Reserved"),
            std::make_pair(6,               "Reserved"),
            std::make_pair(ID::AES128,      "AES128"),
            std::make_pair(ID::AES192,      "AES192"),
            std::make_pair(ID::AES256,      "AES256"),
            std::make_pair(ID::TWOFISH256,  "TWOFISH256"),
            std::make_pair(ID::CAMELLIA128, "CAMELLIA128"),
            std::make_pair(ID::CAMELLIA192, "CAMELLIA192"),
            std::make_pair(ID::CAMELLIA256, "CAMELLIA256"),
            std::make_pair(100,             "Private/Experimental algorithm"),
            std::make_pair(101,             "Private/Experimental algorithm"),
            std::make_pair(102,             "Private/Experimental algorithm"),
            std::make_pair(103,             "Private/Experimental algorithm"),
            std::make_pair(104,             "Private/Experimental algorithm"),
            std::make_pair(105,             "Private/Experimental algorithm"),
            std::make_pair(106,             "Private/Experimental algorithm"),
            std::make_pair(107,             "Private/Experimental algorithm"),
            std::make_pair(108,             "Private/Experimental algorithm"),
            std::make_pair(109,             "Private/Experimental algorithm"),
            std::make_pair(110,             "Private/Experimental algorithm"),
        };

        const std::map <std::string, uint8_t> NUMBER = {
            std::make_pair("PLAINTEXT",     ID::PLAINTEXT),
            std::make_pair("IDEA",          ID::IDEA),
            std::make_pair("TRIPLEDES",     ID::TRIPLEDES),
            std::make_pair("CAST5",         ID::CAST5),
            std::make_pair("BLOWFISH",      ID::BLOWFISH),
            std::make_pair("AES128",        ID::AES128),
            std::make_pair("AES192",        ID::AES192),
            std::make_pair("AES256",        ID::AES256),
            std::make_pair("TWOFISH256",    ID::TWOFISH256),
            std::make_pair("CAMELLIA128",   ID::CAMELLIA128),
            std::make_pair("CAMELLIA192",   ID::CAMELLIA192),
            std::make_pair("CAMELLIA256",   ID::CAMELLIA256),
        };

        const std::map <uint8_t, std::size_t> BLOCK_LENGTH = {
            std::make_pair(ID::IDEA,         64),
            std::make_pair(ID::TRIPLEDES,    64),
            std::make_pair(ID::CAST5,        64),
            std::make_pair(ID::BLOWFISH,     64),
            std::make_pair(ID::AES128,      128),
            std::make_pair(ID::AES192,      128),
            std::make_pair(ID::AES256,      128),
            std::make_pair(ID::TWOFISH256,  128),
            std::make_pair(ID::CAMELLIA128, 128),
            std::make_pair(ID::CAMELLIA192, 128),
            std::make_pair(ID::CAMELLIA256, 128),
        };

        const std::map <uint8_t, std::size_t> KEY_LENGTH = {
            std::make_pair(ID::IDEA,        128),
            std::make_pair(ID::TRIPLEDES,   192),
            std::make_pair(ID::CAST5,       128),
            std::make_pair(ID::BLOWFISH,    128),
            std::make_pair(ID::AES128,      128),
            std::make_pair(ID::AES192,      192),
            std::make_pair(ID::AES256,      256),
            std::make_pair(ID::TWOFISH256,  256),
            std::make_pair(ID::CAMELLIA128, 128),
            std::make_pair(ID::CAMELLIA192, 192),
            std::make_pair(ID::CAMELLIA256, 256),
        };

        bool valid(const uint8_t alg);

        const std::string TDES_mode1 = "e";
        const std::string TDES_mode2 = "d";
        const std::string TDES_mode3 = "e";

        SymAlg::Ptr setup(const uint8_t sym_alg, const std::string & key);
    }
}

#endif
