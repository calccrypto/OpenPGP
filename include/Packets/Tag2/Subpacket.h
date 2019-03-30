/*
Subpacket.h
Base class for OpenPGP Tag 2 Subpackets to inherit from

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

#ifndef __TAG2_SUBPACKET__
#define __TAG2_SUBPACKET__

#include <map>
#include <string>

#include "Packets/Subpacket.h"

namespace OpenPGP {
    namespace Subpacket {
        namespace Tag2 {

            // 5.2.3.1. Signature Subpacket Specification
            //
            //    ...
            //
            //    The value of the Subpacket type octet may be:
            //
            //              0 = Reserved
            //              1 = Reserved
            //              2 = Signature Creation Time
            //              3 = Signature Expiration Time
            //              4 = Exportable Certification
            //              5 = Trust Signature
            //              6 = Regular Expression
            //              7 = Revocable
            //              8 = Reserved
            //              9 = Key Expiration Time
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
            //    An implementation SHOULD ignore any Subpacket of a type that it does
            //    not recognize.
            //
            //    Bit 7 of the Subpacket type is the "critical" bit.  If set, it
            //    denotes that the Subpacket is one that is critical for the evaluator
            //    of the signature to recognize.  If a Subpacket is encountered that is
            //    marked critical but is unknown to the evaluating software, the
            //    evaluator SHOULD consider the signature to be in error.
            //
            //    An evaluator may "recognize" a Subpacket, but not implement it.  The
            //    purpose of the critical bit is to allow the signer to tell an
            //    evaluator that it would prefer a new, unknown feature to generate an
            //    error than be ignored.
            //
            //    Implementations SHOULD implement the three preferred algorithm
            //    Subpackets (11, 21, and 22), as well as the "Reason for Revocation"
            //    Subpacket.  Note, however, that if an implementation chooses not to
            //    implement some of the preferences, it is required to behave in a
            //    polite manner to respect the wishes of those users who do implement
            //    these preferences.

            constexpr uint8_t SIGNATURE_CREATION_TIME                           = 2;
            constexpr uint8_t SIGNATURE_EXPIRATION_TIME                         = 3;
            constexpr uint8_t EXPORTABLE_CERTIFICATION                          = 4;
            constexpr uint8_t TRUST_SIGNATURE                                   = 5;
            constexpr uint8_t REGULAR_EXPRESSION                                = 6;
            constexpr uint8_t REVOCABLE                                         = 7;
            constexpr uint8_t KEY_EXPIRATION_TIME                               = 9;
            constexpr uint8_t PLACEHOLDER_FOR_BACKWARD_COMPATIBILITY            = 10;
            constexpr uint8_t PREFERRED_SYMMETRIC_ALGORITHMS                    = 11;
            constexpr uint8_t REVOCATION_KEY                                    = 12;
            constexpr uint8_t ISSUER                                            = 16;
            constexpr uint8_t NOTATION_DATA                                     = 20;
            constexpr uint8_t PREFERRED_HASH_ALGORITHMS                         = 21;
            constexpr uint8_t PREFERRED_COMPRESSION_ALGORITHMS                  = 22;
            constexpr uint8_t KEY_SERVER_PREFERENCES                            = 23;
            constexpr uint8_t PREFERRED_KEY_SERVER                              = 24;
            constexpr uint8_t PRIMARY_USER_ID                                   = 25;
            constexpr uint8_t POLICY_URI                                        = 26;
            constexpr uint8_t KEY_FLAGS                                         = 27;
            constexpr uint8_t SIGNERS_USER_ID                                   = 28;
            constexpr uint8_t REASON_FOR_REVOCATION                             = 29;
            constexpr uint8_t FEATURES                                          = 30;
            constexpr uint8_t SIGNATURE_TARGET                                  = 31;
            constexpr uint8_t EMBEDDED_SIGNATURE                                = 32;

            #ifdef GPG_COMPATIBLE
            constexpr uint8_t ISSUER_FINGERPRINT                                = 33;
            #endif

            const std::map <uint8_t, std::string> NAME = {
                std::make_pair(0,                                               "Reserved"),
                std::make_pair(1,                                               "Reserved"),
                std::make_pair(SIGNATURE_CREATION_TIME,                         "Signature Creation Time"),
                std::make_pair(SIGNATURE_EXPIRATION_TIME,                       "Signature Expiration Time"),
                std::make_pair(EXPORTABLE_CERTIFICATION,                        "Exportable Certification"),
                std::make_pair(TRUST_SIGNATURE,                                 "Trust Signature"),
                std::make_pair(REGULAR_EXPRESSION,                              "Regular Expression"),
                std::make_pair(REVOCABLE,                                       "Revocable"),
                std::make_pair(8,                                               "Reserved"),
                std::make_pair(KEY_EXPIRATION_TIME,                             "Key Expiration Time"),
                std::make_pair(PLACEHOLDER_FOR_BACKWARD_COMPATIBILITY,          "Placeholder for Backward Compatibility"),       // No Format Defined
                std::make_pair(PREFERRED_SYMMETRIC_ALGORITHMS,                  "Preferred Symmetric Algorithms"),
                std::make_pair(REVOCATION_KEY,                                  "Revocation Key"),
                std::make_pair(13,                                              "Reserved"),
                std::make_pair(14,                                              "Reserved"),
                std::make_pair(15,                                              "Reserved"),
                std::make_pair(ISSUER,                                          "Issuer"),
                std::make_pair(17,                                              "Reserved"),
                std::make_pair(18,                                              "Reserved"),
                std::make_pair(19,                                              "Reserved"),
                std::make_pair(NOTATION_DATA,                                   "Notation Data"),
                std::make_pair(PREFERRED_HASH_ALGORITHMS,                       "Preferred Hash Algorithms"),
                std::make_pair(PREFERRED_COMPRESSION_ALGORITHMS,                "Preferred Compression Algorithms"),
                std::make_pair(KEY_SERVER_PREFERENCES,                          "Key Server Preferences"),
                std::make_pair(PREFERRED_KEY_SERVER,                            "Preferred Key Server"),
                std::make_pair(PRIMARY_USER_ID,                                 "Primary User ID"),
                std::make_pair(POLICY_URI,                                      "Policy URI"),
                std::make_pair(KEY_FLAGS,                                       "Key Flags"),
                std::make_pair(SIGNERS_USER_ID,                                 "Signer's User ID"),
                std::make_pair(REASON_FOR_REVOCATION,                           "Reason for Revocation"),
                std::make_pair(FEATURES,                                        "Features"),
                std::make_pair(SIGNATURE_TARGET,                                "Signature Target"),
                std::make_pair(EMBEDDED_SIGNATURE,                              "Embedded Signature"),

                #ifdef GPG_COMPATIBLE
                std::make_pair(ISSUER_FINGERPRINT,                              "Issuer Fingerprint (GPG extension)"),
                #endif

                std::make_pair(100,                                             "Private/Experimental algorithm"),
                std::make_pair(101,                                             "Private/Experimental algorithm"),
                std::make_pair(102,                                             "Private/Experimental algorithm"),
                std::make_pair(103,                                             "Private/Experimental algorithm"),
                std::make_pair(104,                                             "Private/Experimental algorithm"),
                std::make_pair(105,                                             "Private/Experimental algorithm"),
                std::make_pair(106,                                             "Private/Experimental algorithm"),
                std::make_pair(107,                                             "Private/Experimental algorithm"),
                std::make_pair(108,                                             "Private/Experimental algorithm"),
                std::make_pair(109,                                             "Private/Experimental algorithm"),
                std::make_pair(110,                                             "Private/Experimental algorithm"),
            };

            class Sub: public Subpacket::Sub {
                protected:
                    virtual void actual_read(const std::string & data);
                    std::string show_type() const;
                    virtual void show_contents(HumanReadable & hr) const;

                    Sub(uint8_t type = 0, unsigned int size = 0, bool crit = false);

                public:
                    typedef std::shared_ptr <Sub> Ptr;

                    virtual ~Sub();

                    virtual Ptr clone() const = 0;
            };
        }
    }
}

#endif
