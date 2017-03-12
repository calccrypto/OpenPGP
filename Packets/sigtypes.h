/*
sigtypes.h
Signature types as described in RFC 4880 sec 5.2.1

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

#ifndef __SIGNATURE_TYPES__
#define __SIGNATURE_TYPES__

#include <map>
#include <string>

namespace Signature_Type{
    const uint8_t SIGNATURE_OF_A_BINARY_DOCUMENT                                    = 0X00;
    const uint8_t SIGNATURE_OF_A_CANONICAL_TEXT_DOCUMENT                            = 0X01;
    const uint8_t STANDALONE_SIGNATURE                                              = 0X02;
    const uint8_t GENERIC_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET          = 0X10;
    const uint8_t PERSONA_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET          = 0X11;
    const uint8_t CASUAL_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET           = 0X12;
    const uint8_t POSITIVE_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET         = 0X13;
    const uint8_t SUBKEY_BINDING_SIGNATURE                                          = 0X18;
    const uint8_t PRIMARY_KEY_BINDING_SIGNATURE                                     = 0X19;
    const uint8_t SIGNATURE_DIRECTLY_ON_A_KEY                                       = 0X1F;
    const uint8_t KEY_REVOCATION_SIGNATURE                                          = 0X20;
    const uint8_t SUBKEY_REVOCATION_SIGNATURE                                       = 0X28;
    const uint8_t CERTIFICATION_REVOCATION_SIGNATURE                                = 0X30;
    const uint8_t TIMESTAMP_SIGNATURE                                               = 0X40;
    const uint8_t THIRD_PARTY_CONFIRMATION_SIGNATURE                                = 0X50;

    // NOT PART OF STANDARD
    const uint8_t UNKNOWN                                                           = 0XFF;

    const std::map <uint8_t, std::string> NAME = {
        std::make_pair(SIGNATURE_OF_A_BINARY_DOCUMENT,                              "Signature of a binary document."),
        std::make_pair(SIGNATURE_OF_A_CANONICAL_TEXT_DOCUMENT,                      "Signature of a canonical text document"),
        std::make_pair(STANDALONE_SIGNATURE,                                        "Standalone signature"),
        std::make_pair(GENERIC_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET,    "Generic certification of a User ID and Public-Key packet"),
        std::make_pair(PERSONA_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET,    "Persona certification of a User ID and Public-Key packet"),
        std::make_pair(CASUAL_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET,     "Casual certification of a User ID and Public-Key packet"),
        std::make_pair(POSITIVE_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET,   "Positive certification of a User ID and Public-Key packet"),
        std::make_pair(SUBKEY_BINDING_SIGNATURE,                                    "Subkey Binding Signature"),
        std::make_pair(PRIMARY_KEY_BINDING_SIGNATURE,                               "Primary Key Binding Signature"),
        std::make_pair(SIGNATURE_DIRECTLY_ON_A_KEY,                                 "Signature directly on a key"),
        std::make_pair(KEY_REVOCATION_SIGNATURE,                                    "Key revocation signature"),
        std::make_pair(SUBKEY_REVOCATION_SIGNATURE,                                 "Subkey revocation signature"),
        std::make_pair(CERTIFICATION_REVOCATION_SIGNATURE,                          "Certification revocation signature"),
        std::make_pair(TIMESTAMP_SIGNATURE,                                         "Timestamp signature"),
        std::make_pair(THIRD_PARTY_CONFIRMATION_SIGNATURE,                          "Third-Party Confirmation signature"),
    };

    bool is_signed_document(const uint8_t sig);
    bool is_certification(const uint8_t sig);
    bool is_revocation(const uint8_t sig);
}

#endif
