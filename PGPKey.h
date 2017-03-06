/*
PGPKey.h
OpenPGP Transferable key data structure (RFC 4880 sec 11.1 and 11.2)

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

#ifndef __PGP_KEY__
#define __PGP_KEY__

#include "Packets/packets.h"
#include "PKA/PKAs.h"
#include "PGP.h"

class PGPKey : public PGP {
    private:
        // for listing keys
        const std::map <uint8_t, std::string> Public_Key_Type = {
            std::make_pair( 5, "sec"),
            std::make_pair( 6, "pub"),
            std::make_pair( 7, "ssb"),
            std::make_pair(14, "sub"),
        };

    public:
        typedef std::shared_ptr <PGPKey> Ptr;

        PGPKey();
        PGPKey(const PGP & copy);
        PGPKey(const PGPKey & copy);
        PGPKey(const std::string & data);
        PGPKey(std::istream & stream);
        ~PGPKey();

        std::string keyid()     const; // keyid that is searched for on keyservers
        std::string list_keys() const; // output is copied from gpg --list-keys

        // whether or not data matches a Key format
        bool meaningful(std::string & error) const;
        using PGP::meaningful;

        virtual PGP::Ptr clone() const;
};

std::ostream & operator <<(std::ostream & stream, const PGPKey & pgp);

// 11.1. Transferable Public Keys
//
//    OpenPGP users may transfer public keys. The essential elements of a
//    transferable public key are as follows:
//
//      - One Public-Key packet
//
//      - Zero or more revocation signatures
//
//      - One or more User ID packets
//
//      - After each User ID packet, zero or more Signature packets (certifications)
//
//      - Zero or more User Attribute packets
//
//      - After each User Attribute packet, zero or more Signature packets (certifications)
//
//      - Zero or more Subkey packets
//
//      - After each Subkey packet, one Signature packet, plus optionally a revocation
//
//    The Public-Key packet occurs first. Each of the following User ID
//    packets provides the identity of the owner of this public key. If
//    there are multiple User ID packets, this corresponds to multiple
//    means of identifying the same unique individual user; for example, a
//    user may have more than one email address, and construct a User ID
//    for each one.
//
//    Immediately following each User ID packet, there are zero or more
//    Signature packets. Each Signature packet is calculated on the
//    immediately preceding User ID packet and the initial Public-Key
//    packet. The signature serves to certify the corresponding public key
//    and User ID. In effect, the signer is testifying to his or her
//    belief that this public key belongs to the user identified by this
//    User ID.
//
//    Within the same section as the User ID packets, there are zero or
//    more User Attribute packets. Like the User ID packets, a User
//    Attribute packet is followed by zero or more Signature packets
//    calculated on the immediately preceding User Attribute packet and the
//    initial Public-Key packet.
//
//    User Attribute packets and User ID packets may be freely intermixed
//    in this section, so long as the signatures that follow them are
//    maintained on the proper User Attribute or User ID packet.
//    After the User ID packet or Attribute packet, there may be zero or
//    more Subkey packets. In general, subkeys are provided in cases where
//    the top-level public key is a signature-only key. However, any V4
//    key may have subkeys, and the subkeys may be encryption-only keys,
//    signature-only keys, or general-purpose keys. V3 keys MUST NOT have
//    subkeys.
//
//    Each Subkey packet MUST be followed by one Signature packet, which
//    should be a subkey binding signature issued by the top-level key.
//    For subkeys that can issue signatures, the subkey binding signature
//    MUST contain an Embedded Signature subpacket with a primary key
//    binding signature (0x19) issued by the subkey on the top-level key.
//    Subkey and Key packets may each be followed by a revocation Signature
//    packet to indicate that the key is revoked. Revocation signatures
//    are only accepted if they are issued by the key itself, or by a key
//    that is authorized to issue revocations via a Revocation Key
//    subpacket in a self-signature by the top-level key.
//
//    Transferable public-key packet sequences may be concatenated to allow
//    transferring multiple public keys in one operation.

class PGPSecretKey;
class PGPPublicKey : public PGPKey {
    public:
        typedef std::shared_ptr <PGPPublicKey> Ptr;

        PGPPublicKey();
        PGPPublicKey(const PGPKey & copy);
        PGPPublicKey(const PGPPublicKey & copy);
        PGPPublicKey(const std::string & data);
        PGPPublicKey(std::istream & stream);
        PGPPublicKey(const PGPSecretKey & sec);
        ~PGPPublicKey();

        // whether or not data matches the Public Key format
        bool meaningful(std::string & error) const;
        using PGPKey::meaningful;

        PGPPublicKey & operator=(const PGPPublicKey & pub);
        PGPPublicKey & operator=(const PGPSecretKey & pri);

        PGP::Ptr clone() const;
};

std::ostream & operator <<(std::ostream & stream, const PGPPublicKey & pgp);

// 11.2. Transferable Secret Keys
//
//    OpenPGP users may transfer secret keys. The format of a transferable
//    secret key is the same as a transferable public key except that
//    secret-key and secret-subkey packets are used instead of the public
//    key and public-subkey packets. Implementations SHOULD include self-
//    signatures on any user IDs and subkeys, as this allows for a complete
//    public key to be automatically extracted from the transferable secret
//    key. Implementations MAY choose to omit the self-signatures,
//    especially if a transferable public key accompanies the transferable
//    secret key.

class PGPSecretKey : public PGPKey {
    public:
        typedef std::shared_ptr <PGPSecretKey> Ptr;

        PGPSecretKey();
        PGPSecretKey(const PGPKey & copy);
        PGPSecretKey(const PGPSecretKey & copy);
        PGPSecretKey(const std::string & data);
        PGPSecretKey(std::istream & stream);
        ~PGPSecretKey();

        // Extract Public Key data from a Secret Key
        PGPPublicKey get_public() const;

        // whether or not data matches Secret Key format
        bool meaningful(std::string & error) const;
        using PGPKey::meaningful;

        PGP::Ptr clone() const;
};

std::ostream & operator <<(std::ostream & stream, const PGPSecretKey & pgp);

// Search PGP keys for signing keys
Key::Ptr find_signing_key(const PGPKey & key, const uint8_t tag);

#endif