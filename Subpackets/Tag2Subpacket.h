/*
Tag2Subpacket.h
Base class for OpenPGP Tag 2 subpackets to inherit from

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

#ifndef __TAG2_SUBPACKET__
#define __TAG2_SUBPACKET__

#include <map>
#include <string>

#include "Subpacket.h"

// 5.2.3.1. Signature Subpacket Specification
//
//    ...
//
//    The value of the subpacket type octet may be:
//
//             0 = Reserved
//             1 = Reserved
//             2 = Signature Creation Time
//             3 = Signature Expiration Time
//             4 = Exportable Certification
//             5 = Trust Signature
//             6 = Regular Expression
//             7 = Revocable
//             8 = Reserved
//             9 = Key Expiration Time
//             10 = Placeholder for backward compatibility
//             11 = Preferred Symmetric Algorithms
//             12 = Revocation Key
//             13 = Reserved
//             14 = Reserved
//             15 = Reserved
//             16 = Issuer
//             17 = Reserved
//             18 = Reserved
//             19 = Reserved
//             20 = Notation Data
//             21 = Preferred Hash Algorithms
//             22 = Preferred Compression Algorithms
//             23 = Key Server Preferences
//             24 = Preferred Key Server
//             25 = Primary User ID
//             26 = Policy URI
//             27 = Key Flags
//             28 = Signer’s User ID
//             29 = Reason for Revocation
//             30 = Features
//             31 = Signature Target
//             32 = Embedded Signature
//     100 To 110 = Private or experimental
//

class Tag2Subpacket: public Subpacket {
    public:
        class ID{
            public:
                static const uint8_t Signature_Creation_Time;
                static const uint8_t Signature_Expiration_Time;
                static const uint8_t Exportable_Certification;
                static const uint8_t Trust_Signature;
                static const uint8_t Regular_Expression;
                static const uint8_t Revocable;
                static const uint8_t Key_Expiration_Time;
                static const uint8_t Placeholder_for_Backward_Compatibility;
                static const uint8_t Preferred_Symmetric_Algorithms;
                static const uint8_t Revocation_Key;
                static const uint8_t Issuer;
                static const uint8_t Notation_Data;
                static const uint8_t Preferred_Hash_Algorithms;
                static const uint8_t Preferred_Compression_Algorithms;
                static const uint8_t Key_Server_Preferences;
                static const uint8_t Preferred_Key_Server;
                static const uint8_t Primary_User_ID;
                static const uint8_t Policy_URI;
                static const uint8_t Key_Flags;
                static const uint8_t Signers_User_ID;
                static const uint8_t Reason_for_Revocation;
                static const uint8_t Features;
                static const uint8_t Signature_Target;
                static const uint8_t Embedded_Signature;
        };

        static const std::map <uint8_t, std::string> Name;

    protected:
        using Subpacket::Subpacket;

        std::string show_title() const;

        Tag2Subpacket & operator=(const Tag2Subpacket & copy);

    public:
        typedef std::shared_ptr <Tag2Subpacket> Ptr;

        virtual ~Tag2Subpacket();

        virtual Ptr clone() const = 0;
};

#endif