/*
PKAs.h
List of Public Key Algorithm headers

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

#ifndef __PKAS__
#define __PKAS__

#include <map>
#include <stdexcept>

// 9.1.  Public-Key Algorithms
//
//       ID           Algorithm
//       --           ---------
//       1          - RSA (Encrypt or Sign) [HAC]
//       2          - RSA Encrypt-Only [HAC]
//       3          - RSA Sign-Only [HAC]
//       16         - Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
//       17         - DSA (Digital Signature Algorithm) [FIPS186] [HAC]
//       18         - Reserved for Elliptic Curve
//       19         - Reserved for ECDSA
//       20         - Reserved (formerly Elgamal Encrypt or Sign)
//       21         - Reserved for Diffie-Hellman (X9.42,
//                    as defined for IETF-S/MIME)
//       100 to 110 - Private/Experimental algorithm

#include "PKA.h"

#include "DSA.h"
#include "ElGamal.h"
#include "RSA.h"

namespace PKA{
    namespace ID{
        const uint8_t RSA_Encrypt_or_Sign = 1;
        const uint8_t RSA_Encrypt_Only    = 2;
        const uint8_t RSA_Sign_Only       = 3;
        const uint8_t ElGamal             = 16;
        const uint8_t DSA                 = 17;
    }

    const std::map <uint8_t, std::string> Name = {
        std::make_pair(ID::RSA_Encrypt_or_Sign, "RSA (Encrypt or Sign)"),
        std::make_pair(ID::RSA_Encrypt_Only,    "RSA Encrypt-Only"),       // deprecated
        std::make_pair(ID::RSA_Sign_Only,       "RSA Sign-Only"),          // deprecated
        std::make_pair(ID::ElGamal,             "ElGamal (Encrypt-Only)"),
        std::make_pair(ID::DSA,                 "DSA"),
        std::make_pair(18,                      "Reserved for Elliptic Curve"),
        std::make_pair(19,                      "Reserved for ECDSA"),
        std::make_pair(20,                      "Reserved (formerly ElGamal Encrypt or Sign)"),
        std::make_pair(21,                      "Reserved for Diffie-Hellman (X9.42), as defined for IETF-S / MIME)"),
        std::make_pair(100,                     "Private/Experimental algorithm"),
        std::make_pair(101,                     "Private/Experimental algorithm"),
        std::make_pair(102,                     "Private/Experimental algorithm"),
        std::make_pair(103,                     "Private/Experimental algorithm"),
        std::make_pair(104,                     "Private/Experimental algorithm"),
        std::make_pair(105,                     "Private/Experimental algorithm"),
        std::make_pair(106,                     "Private/Experimental algorithm"),
        std::make_pair(107,                     "Private/Experimental algorithm"),
        std::make_pair(108,                     "Private/Experimental algorithm"),
        std::make_pair(109,                     "Private/Experimental algorithm"),
        std::make_pair(110,                     "Private/Experimental algorithm"),
    };

    const std::map <uint8_t, char> Short = {
        std::make_pair(ID::RSA_Encrypt_or_Sign, 'R'),
        std::make_pair(ID::RSA_Encrypt_Only,    'R'),
        std::make_pair(ID::RSA_Sign_Only,       'R'),
        std::make_pair(ID::ElGamal,             'g'),
        std::make_pair(ID::DSA,                 'D'),
    };

    bool can_encrypt(const uint8_t alg);
    bool can_sign(const uint8_t alg);
    bool is_RSA(const uint8_t alg);
}

/*
param:
    DSA = {L, N}
    ElGamal = {bits}
    RSA = {bits}

pub and pri are destination containers
*/
void generate_key_pair(const uint8_t pka, const PKA::Params & params, PKA::Values & pub, PKA::Values & pri);

#endif
