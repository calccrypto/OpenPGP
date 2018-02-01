/*
sigcalc.h
Calculates signature data as described in RFC 4880 sec 5.2.1 and 5.2.4

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

#ifndef __SIGNATURE__
#define __SIGNATURE__

#include <sstream>
#include <stdexcept>
#include <string>

#include "../Hashes/Hashes.h"
#include "../Packets/packets.h"
#include "pgptime.h"

namespace OpenPGP {
    // Modify data for signature version 3 or 4
    //
    //    Once the data body is hashed, then a trailer is hashed. A V3
    //    signature hashes five octets of the packet body, starting from the
    //    signature type field. This data is the signature type, followed by
    //    the four-octet signature time. A V4 signature hashes the packet body
    //    starting from its first field, the version number, through the end
    //    of the hashed subpacket data. Thus, the fields hashed are the
    //    signature version, the signature type, the public-key algorithm, the
    //    hash algorithm, the hashed subpacket length, and the hashed
    //    subpacket body.
    //
    //    V4 signatures also hash in a final trailer of six octets: the
    //    version of the Signature packet, i.e., 0x04; 0xFF; and a four-octet,
    //    big-endian number that is the length of the hashed data from the
    //    Signature packet (note that this number does not include these final
    //    six octets).
    //
    //    After all this has been hashed in a single hash context, the
    //    resulting hash field is used in the signature algorithm and placed
    //    at the end of the Signature packet.
    std::string addtrailer(const std::string & data, const Packet::Tag2::Ptr & sig);

    // Signature over a Packet::Key
    //
    //    When a signature is made over a Packet::Key, the hash data starts with the
    //    octet 0x99, followed by a two-octet length of the Packet::Key, and then body
    //    of the Packet::Key packet. (Note that this is an old-style packet header for
    //    a Packet::Key packet with two-octet length.)
    std::string overkey(const Packet::Key::Ptr & key);

    // Signature Type 0x10 - 0x13
    //
    //    A certification signature (type 0x10 through 0x13) hashes the User
    //    ID being bound to the Packet::Key into the hash context after the above
    //    data. A V3 certification hashes the contents of the User ID or
    //    attribute packet packet, without any header. A V4 certification
    //    hashes the constant 0xB4 for User ID certifications or the constant
    //    0xD1 for User Attribute certifications, followed by a four-octet
    //    number giving the length of the User ID or User Attribute data, and
    //    then the User ID or User Attribute data.
    std::string certification(uint8_t version, const Packet::User::Ptr & id);

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
    // 0x00: Signature of a binary document.
    //    This means the signer owns it, created it, or certifies that it
    //    has not been modified.
    //
    //    For binary document signatures (type 0x00), the document data is
    //    hashed directly.
    const std::string & binary_to_canonical(const std::string & data);
    std::string to_sign_00(const std::string & data, const Packet::Tag2::Ptr & tag2);

    // 0x01: Signature of a canonical text document.
    //    This means the signer owns it, created it, or certifies that it
    //    has not been modified. The signature is calculated over the text
    //    data with its line endings converted to <CR><LF>.
    //
    //    For text document signatures (type 0x01), the
    //    document is canonicalized by converting line endings to <CR><LF>,
    //    and the resulting data is hashed.
    std::string text_to_canonical(const std::string & data);
    std::string to_sign_01(const std::string & data, const Packet::Tag2::Ptr & tag2);

    // 0x02: Standalone signature.
    //    This signature is a signature of only its own subpacket contents.
    //    It is calculated identically to a signature over a zero-length
    //    binary document. Note that it doesn't make sense to have a V3
    //    standalone signature.
    std::string to_sign_02(const Packet::Tag2::Ptr & tag2);

    // 0x10: Generic certification of a User ID and Public-Key packet.
    //    The issuer of this certification does not make any particular
    //    assertion as to how well the certifier has checked that the owner
    //    of the Packet::Key is in fact the person described by the User ID.
    std::string to_sign_10(const Packet::Key::Ptr & key, const Packet::User::Ptr & id, const Packet::Tag2::Ptr & tag2);

    // 0x11: Persona certification of a User ID and Public-Key packet.
    //    The issuer of this certification has not done any verification of
    //    the claim that the owner of this Packet::Key is the User ID specified.
    std::string to_sign_11(const Packet::Key::Ptr & key, const Packet::User::Ptr & id, const Packet::Tag2::Ptr & tag2);

    // 0x12: Casual certification of a User ID and Public-Key packet.
    //    The issuer of this certification has done some casual
    //    verification of the claim of identity.
    std::string to_sign_12(const Packet::Key::Ptr & key, const Packet::User::Ptr & id, const Packet::Tag2::Ptr & tag2);

    // 0x13: Positive certification of a User ID and Public-Key packet.
    //    The issuer of this certification has done substantial
    //    verification of the claim of identity.
    //
    //    Most OpenPGP implementations make their "key signatures" as 0x10
    //    certifications. Some implementations can issue 0x11-0x13
    //    certifications, but few differentiate between the types.
    std::string to_sign_13(const Packet::Key::Ptr & key, const Packet::User::Ptr & id, const Packet::Tag2::Ptr & tag2);

    // combine signing 0x10, 0x11, 0x12, and 0x13, since they are all the same
    std::string to_sign_cert(const uint8_t cert, const Packet::Key::Ptr & key, const Packet::User::Ptr & id, const Packet::Tag2::Ptr & sig);

    // 0x18: Subkey Binding Signature
    //    This signature is a statement by the top-level signing Packet::Key that
    //    indicates that it owns the subkey. This signature is calculated
    //    directly on the primary Packet::Key and subkey, and not on any User ID or
    //    other packets. A signature that binds a signing subkey MUST have
    //    an Embedded Signature subpacket in this binding signature that
    //    contains a 0x19 signature made by the signing subkey on the
    //    primary Packet::Key and subkey.
    std::string to_sign_18(const Packet::Key::Ptr & primary, const Packet::Key::Ptr & key, const Packet::Tag2::Ptr & tag2);

    // 0x19: Primary Packet::Key Binding Signature
    //    This signature is a statement by a signing subkey, indicating
    //    that it is owned by the primary Packet::Key and subkey. This signature
    //    is calculated the same way as a 0x18 signature: directly on the
    //    primary Packet::Key and subkey, and not on any User ID or other packets.
    std::string to_sign_19(const Packet::Key::Ptr & primary, const Packet::Key::Ptr & subkey, const Packet::Tag2::Ptr & tag2);

    // 0x1F: Signature directly on a Packet::Key
    //    This signature is calculated directly on a Packet::Key. It binds the
    //    information in the Signature subpackets to the Packet::Key, and is
    //    appropriate to be used for subpackets that provide information
    //    about the Packet::Key, such as the Revocation Packet::Key subpacket. It is also
    //    appropriate for statements that non-self certifiers want to make
    //    about the Packet::Key itself, rather than the binding between a Packet::Key and a
    //    name.
    std::string to_sign_1f(const Packet::Key::Ptr & k, const Packet::Tag2::Ptr & tag2);

    // 0x20: Packet::Key revocation signature
    //    The signature is calculated directly on the Packet::Key being revoked. A
    //    revoked Packet::Key is not to be used. Only revocation signatures by the
    //    Packet::Key being revoked, or by an authorized revocation Packet::Key, should be
    //    considered valid revocation signatures.
    std::string to_sign_20(const Packet::Key::Ptr & key, const Packet::Tag2::Ptr & tag2);

    // 0x28: Subkey revocation signature
    //    The signature is calculated directly on the subkey being revoked.
    //    A revoked subkey is not to be used. Only revocation signatures
    //    by the top-level signature Packet::Key that is bound to this subkey, or
    //    by an authorized revocation Packet::Key, should be considered valid
    //    revocation signatures.
    std::string to_sign_28(const Packet::Key::Ptr & subkey, const Packet::Tag2::Ptr & tag2);

    // 0x30: Certification revocation signature
    //    This signature revokes an earlier User ID certification signature
    //    (signature class 0x10 through 0x13) or direct-key signature
    //    (0x1F). It should be issued by the same Packet::Key that issued the
    //    revoked signature or an authorized revocation Packet::Key. The signature
    //    is computed over the same data as the certificate that it
    //    revokes, and should have a later creation date than that
    //    certificate.
    std::string to_sign_30(const Packet::Key::Ptr & key, const Packet::User::Ptr & id, const Packet::Tag2::Ptr & tag2);

    // 0x40: Timestamp signature.
    //    This signature is only meaningful for the timestamp contained in
    //    it.
    std::string to_sign_40(const Packet::Tag2::Ptr & tag2);

    // 0x50: Third-Party Confirmation signature.
    //    This signature is a signature over some other OpenPGP Signature
    //    packet(s). It is analogous to a notary seal on the signed data.
    //    A third-party signature SHOULD include Signature Target
    //    subpacket(s) to give easy identification. Note that we really do
    //    mean SHOULD. There are plausible uses for this (such as a blind
    //    party that only sees the signature, not the Packet::Key or source
    //    document) that cannot include a target subpacket.
    //
    //    When a signature is made over a Signature packet (type 0x50), the
    //    hash data starts with the octet 0x88, followed by the four-octet
    //    length of the signature, and then the body of the Signature packet.
    //    (Note that this is an old-style packet header for a Signature packet
    //    with the length-of-length set to zero.) The unhashed subpacket data
    //    of the Signature packet being hashed is not included in the hash, and
    //    the unhashed subpacket data length value is set to zero.
    std::string to_sign_50(const Packet::Tag2 & sig, const Packet::Tag2::Ptr & tag2);

}

#endif