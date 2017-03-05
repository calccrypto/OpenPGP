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
//

namespace Signature_Type{
    namespace ID{
        const uint8_t Signature_of_a_binary_document                                    = 0x00;
        const uint8_t Signature_of_a_canonical_text_document                            = 0x01;
        const uint8_t Standalone_signature                                              = 0x02;
        const uint8_t Generic_certification_of_a_User_ID_and_Public_Key_packet          = 0x10;
        const uint8_t Persona_certification_of_a_User_ID_and_Public_Key_packet          = 0x11;
        const uint8_t Casual_certification_of_a_User_ID_and_Public_Key_packet           = 0x12;
        const uint8_t Positive_certification_of_a_User_ID_and_Public_Key_packet         = 0x13;
        const uint8_t Subkey_Binding_Signature                                          = 0x18;
        const uint8_t Primary_Key_Binding_Signature                                     = 0x19;
        const uint8_t Signature_directly_on_a_key                                       = 0x1f;
        const uint8_t Key_revocation_signature                                          = 0x20;
        const uint8_t Subkey_revocation_signature                                       = 0x28;
        const uint8_t Certification_revocation_signature                                = 0x30;
        const uint8_t Timestamp_signature                                               = 0x40;
        const uint8_t Third_Party_Confirmation_signature                                = 0x50;
    }

    const std::map <uint8_t, std::string> Name = {
        std::make_pair(ID::Signature_of_a_binary_document,                              "Signature of a binary document."),
        std::make_pair(ID::Signature_of_a_canonical_text_document,                      "Signature of a canonical text document"),
        std::make_pair(ID::Standalone_signature,                                        "Standalone signature"),
        std::make_pair(ID::Generic_certification_of_a_User_ID_and_Public_Key_packet,    "Generic certification of a User ID and Public-Key packet"),
        std::make_pair(ID::Persona_certification_of_a_User_ID_and_Public_Key_packet,    "Persona certification of a User ID and Public-Key packet"),
        std::make_pair(ID::Casual_certification_of_a_User_ID_and_Public_Key_packet,     "Casual certification of a User ID and Public-Key packet"),
        std::make_pair(ID::Positive_certification_of_a_User_ID_and_Public_Key_packet,   "Positive certification of a User ID and Public-Key packet"),
        std::make_pair(ID::Subkey_Binding_Signature,                                    "Subkey Binding Signature"),
        std::make_pair(ID::Primary_Key_Binding_Signature,                               "Primary Key Binding Signature"),
        std::make_pair(ID::Signature_directly_on_a_key,                                 "Signature directly on a key"),
        std::make_pair(ID::Key_revocation_signature,                                    "Key revocation signature"),
        std::make_pair(ID::Subkey_revocation_signature,                                 "Subkey revocation signature"),
        std::make_pair(ID::Certification_revocation_signature,                          "Certification revocation signature"),
        std::make_pair(ID::Timestamp_signature,                                         "Timestamp signature"),
        std::make_pair(ID::Third_Party_Confirmation_signature,                          "Third-Party Confirmation signature"),
    };
}

#endif
