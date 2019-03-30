/*
Hashes.h
File to include to make hash algorithms available.

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

#ifndef HASHES_H
#define HASHES_H

#include <map>
#include <memory>

#include "Hashes/Alg.h"

#include "Hashes/MD5.h"
#include "Hashes/RIPEMD160.h"
#include "Hashes/SHA1.h"
#include "Hashes/SHA256.h"
#include "Hashes/SHA224.h"
#include "Hashes/SHA512.h"
#include "Hashes/SHA384.h"

namespace OpenPGP {
    namespace Hash {

        // 9.4. Hash Algorithms
        //
        //      ID           Algorithm                             Text Name
        //      --           ---------                             ---------
        //      1          - MD5 [HAC]                             "MD5"
        //      2          - SHA-1 [FIPS180]                       "SHA1"
        //      3          - RIPE-MD/160 [HAC]                     "RIPEMD160"
        //      4          - Reserved
        //      5          - Reserved
        //      6          - Reserved
        //      7          - Reserved
        //      8          - SHA256 [FIPS180]                      "SHA256"
        //      9          - SHA384 [FIPS180]                      "SHA384"
        //      10         - SHA512 [FIPS180]                      "SHA512"
        //      11         - SHA224 [FIPS180]                      "SHA224"
        //      100 to 110 - Private/Experimental algorithm
        //
        //    Implementations MUST implement SHA-1. Implementations MAY implement
        //    other algorithms. MD5 is deprecated.

        namespace ID {
            constexpr uint8_t MD5           = 1;
            constexpr uint8_t SHA1          = 2;
            constexpr uint8_t RIPEMD160     = 3;
            constexpr uint8_t SHA256        = 8;
            constexpr uint8_t SHA384        = 9;
            constexpr uint8_t SHA512        = 10;
            constexpr uint8_t SHA224        = 11;
        }

        const std::map <uint8_t, std::string> NAME = {
            std::make_pair(ID::MD5,         "MD5"),
            std::make_pair(ID::SHA1,        "SHA1"),
            std::make_pair(ID::RIPEMD160,   "RIPEMD160"),
            std::make_pair(4,               "Reserved"),
            std::make_pair(5,               "Reserved"),
            std::make_pair(6,               "Reserved"),
            std::make_pair(7,               "Reserved"),
            std::make_pair(ID::SHA256,      "SHA256"),
            std::make_pair(ID::SHA384,      "SHA384"),
            std::make_pair(ID::SHA512,      "SHA512"),
            std::make_pair(ID::SHA224,      "SHA224"),
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
            std::make_pair("MD5",           ID::MD5),
            std::make_pair("SHA1",          ID::SHA1),
            std::make_pair("RIPEMD160",     ID::RIPEMD160),
            std::make_pair("SHA256",        ID::SHA256),
            std::make_pair("SHA384",        ID::SHA384),
            std::make_pair("SHA512",        ID::SHA512),
            std::make_pair("SHA224",        ID::SHA224),
        };

        // ASN.1 OIDs in hex form
        const std::map <uint8_t, std::string> ASN1_DER = {
            std::make_pair(ID::MD5,         "3020300C06082A864886F70D020505000410"),    // 1.2.840.113549.2.5
            std::make_pair(ID::RIPEMD160,   "3021300906052B2403020105000414"),          // 1.3.36.3.2.1
            std::make_pair(ID::SHA1,        "3021300906052B0E03021A05000414"),          // 1.3.14.3.2.26
            std::make_pair(ID::SHA224,      "302D300d06096086480165030402040500041C"),  // 2.16.840.1.101.3.4.2.4
            std::make_pair(ID::SHA256,      "3031300d060960864801650304020105000420"),  // 2.16.840.1.101.3.4.2.1
            std::make_pair(ID::SHA384,      "3041300d060960864801650304020205000430"),  // 2.16.840.1.101.3.4.2.2
            std::make_pair(ID::SHA512,      "3051300d060960864801650304020305000440"),  // 2.16.840.1.101.3.4.2.3
        };

        const std::map <uint8_t, std::size_t> LENGTH = {
            std::make_pair(ID::MD5,         128),
            std::make_pair(ID::SHA1,        160),
            std::make_pair(ID::RIPEMD160,   160),
            std::make_pair(ID::SHA256,      256),
            std::make_pair(ID::SHA384,      384),
            std::make_pair(ID::SHA512,      512),
            std::make_pair(ID::SHA224,      224),
        };

        bool valid(const uint8_t alg);

        std::string use(const uint8_t alg, const std::string & data = "");

        typedef std::shared_ptr <Alg> Instance;
        Instance get_instance(const uint8_t alg, const std::string & data = "");
    }
}

#endif
