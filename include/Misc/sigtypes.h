/*
sigtypes.h
Signature types as described in RFC 4880 sec 5.2.1

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

#ifndef __SIGNATURE_TYPES__
#define __SIGNATURE_TYPES__

#include <map>
#include <string>

namespace OpenPGP {
    // 5.2.1. Signature Types
    //    There are a number of possible meanings for a signature, which are
    //    indicated in a signature type octet in any given signature. Please
    //    note that the vagueness of these meanings is not a flaw, but a
    //    feature of the system. Because OpenPGP places final authority for
    //    validity upon the receiver of a signature, it may be that one
    //    signer’s casual act might be more rigorous than some other
    //    authority’s positive act. See Section 5.2.4, "Computing Signatures",
    //    for detailed information on how to compute and verify signatures of
    //    each type.
    //
    //    These meanings are as follows:
    //
    //    0x00: Signature of a binary document.
    //        This means the signer owns it, created it, or certifies that it
    //        has not been modified.
    //
    //    0x01: Signature of a canonical text document.
    //        This means the signer owns it, created it, or certifies that it
    //        has not been modified. The signature is calculated over the text
    //        data with its line endings converted to <CR><LF>.
    //
    //    0x02: Standalone signature.
    //        This signature is a signature of only its own subpacket contents.
    //        It is calculated identically to a signature over a zero-length
    //        binary document. Note that it doesn’t make sense to have a V3
    //        standalone signature.
    //
    //    0x10: Generic certification of a User ID and Public-Key packet.
    //        The issuer of this certification does not make any particular
    //        assertion as to how well the certifier has checked that the owner
    //        of the key is in fact the person described by the User ID.
    //
    //    0x11: Persona certification of a User ID and Public-Key packet.
    //        The issuer of this certification has not done any verification of
    //        the claim that the owner of this key is the User ID specified.
    //
    //    0x12: Casual certification of a User ID and Public-Key packet.
    //        The issuer of this certification has done some casual
    //        verification of the claim of identity.
    //
    //    0x13: Positive certification of a User ID and Public-Key packet.
    //        The issuer of this certification has done substantial
    //        verification of the claim of identity.
    //
    //        Most OpenPGP implementations make their "key signatures" as 0x10
    //        certifications. Some implementations can issue 0x11-0x13
    //        certifications, but few differentiate between the types.
    //
    //    0x18: Subkey Binding Signature
    //        This signature is a statement by the top-level signing key that
    //        indicates that it owns the subkey. This signature is calculated
    //        directly on the primary key and subkey, and not on any User ID or
    //        other packets. A signature that binds a signing subkey MUST have
    //        an Embedded Signature subpacket in this binding signature that
    //        contains a 0x19 signature made by the signing subkey on the
    //        primary key and subkey.
    //
    //    0x19: Primary Key Binding Signature
    //        This signature is a statement by a signing subkey, indicating
    //        that it is owned by the primary key and subkey. This signature
    //        is calculated the same way as a 0x18 signature: directly on the
    //        primary key and subkey, and not on any User ID or other packets.
    //
    //    0x1F: Signature directly on a key
    //        This signature is calculated directly on a key. It binds the
    //        information in the Signature subpackets to the key, and is
    //        appropriate to be used for subpackets that provide information
    //        about the key, such as the Revocation Key subpacket. It is also
    //        appropriate for statements that non-self certifiers want to make
    //        about the key itself, rather than the binding between a key and a
    //        name.
    //
    //    0x20: Key revocation signature
    //        The signature is calculated directly on the key being revoked. A
    //        revoked key is not to be used. Only revocation signatures by the
    //        key being revoked, or by an authorized revocation key, should be
    //        considered valid revocation signatures.
    //
    //    0x28: Subkey revocation signature
    //        The signature is calculated directly on the subkey being revoked.
    //        A revoked subkey is not to be used. Only revocation signatures
    //        by the top-level signature key that is bound to this subkey, or
    //        by an authorized revocation key, should be considered valid
    //        revocation signatures.
    //
    //    0x30: Certification revocation signature
    //        This signature revokes an earlier User ID certification signature
    //        (signature class 0x10 through 0x13) or direct-key signature
    //        (0x1F). It should be issued by the same key that issued the
    //        revoked signature or an authorized revocation key. The signature
    //        is computed over the same data as the certificate that it
    //        revokes, and should have a later creation date than that
    //        certificate.
    //
    //    0x40: Timestamp signature.
    //        This signature is only meaningful for the timestamp contained in
    //        it.
    //
    //    0x50: Third-Party Confirmation signature.
    //        This signature is a signature over some other OpenPGP Signature
    //        packet(s). It is analogous to a notary seal on the signed data.
    //        A third-party signature SHOULD include Signature Target
    //        subpacket(s) to give easy identification. Note that we really do
    //        mean SHOULD. There are plausible uses for this (such as a blind
    //        party that only sees the signature, not the key or source
    //        document) that cannot include a target subpacket.

    namespace Signature_Type {
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

        // not part of standard
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
}

#endif
