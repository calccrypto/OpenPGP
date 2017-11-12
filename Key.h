/*
Key.h
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

#ifndef __OPENPGP_KEY__
#define __OPENPGP_KEY__

#include <set>
#include "Packets/packets.h"
#include "PKA/PKAs.h"
#include "PGP.h"

namespace OpenPGP {
    class Key : public PGP {
        public:
            typedef std::multimap<Packet::Tag::Ptr, Packet::Tag::Ptr> SigPairs; // Map between two packets

            struct pkey{ // struct contains mapping between packets and relative signatures
                Packet::Tag::Ptr key;   // Primary Key
                SigPairs keySigs;       // Map between Primary Key and Signatures
                SigPairs uids;          // Map between User (include UserID and User Attributes) and Signatures
                SigPairs subKeys;       // Map between Subkeys and Signatures
                SigPairs uid_userAtt;   // Map between UserID and User Attributes
            };
        private:
            // for listing keys
            const std::map <uint8_t, std::string> Public_Key_Type = {
                std::make_pair(Packet::SECRET_KEY,    "sec"),
                std::make_pair(Packet::PUBLIC_KEY,    "pub"),
                std::make_pair(Packet::SECRET_SUBKEY, "ssb"),
                std::make_pair(Packet::PUBLIC_SUBKEY, "sub"),
            };

            // Extract Packet from sp pushing them in np
            void flatten(SigPairs sp, Packets *np, SigPairs ua_table);

        public:
            typedef std::shared_ptr <Key> Ptr;

            Key();
            Key(const PGP & copy);
            Key(const Key & copy);
            Key(const std::string & data);
            Key(std::istream & stream);
            ~Key();

            // keyid that is searched for on keyservers
            std::string keyid() const;

            // fingerprint of entire key (primary key packet)
            std::string fingerprint() const;

            // version of entire key (primary key packet)
            uint8_t version() const;

            // output style inspired by gpg and SKS Keyserver/pgp.mit.edu
            std::string list_keys(const std::size_t indents = 0, const std::size_t indent_size = 4) const;

            // whether or not PGP data matches a Key format without constructing a new object
            static bool meaningful(const PGP & pgp);

            // whether or not *this data matches a Key format
            virtual bool meaningful() const;

            // return the pkey format of the key
            pkey get_pkey() const;

            // Merge function ported from sks keyserver ocaml code
            void merge(Key::Ptr k);

            virtual PGP::Ptr clone() const;
        };

    std::ostream & operator <<(std::ostream & stream, const Key & pgp);

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

    class SecretKey;
    class PublicKey : public Key {
        public:
            typedef std::shared_ptr <PublicKey> Ptr;

            PublicKey();
            PublicKey(const Key & copy);
            PublicKey(const PublicKey & copy);
            PublicKey(const std::string & data);
            PublicKey(std::istream & stream);
            PublicKey(const SecretKey & sec);
            ~PublicKey();

            // whether or not data matches the Public Key format
            bool meaningful() const;

            PublicKey & operator=(const PublicKey & pub);
            PublicKey & operator=(const SecretKey & pri);

            PGP::Ptr clone() const;
    };

    std::ostream & operator <<(std::ostream & stream, const PublicKey & pgp);

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

    class SecretKey : public Key {
        public:
            typedef std::shared_ptr <SecretKey> Ptr;

            SecretKey();
            SecretKey(const Key & copy);
            SecretKey(const SecretKey & copy);
            SecretKey(const std::string & data);
            SecretKey(std::istream & stream);
            ~SecretKey();

            // Extract Public Key data from a Secret Key
            PublicKey get_public() const;

            // whether or not data matches Secret Key format
            bool meaningful() const;

            PGP::Ptr clone() const;
    };

    std::ostream & operator <<(std::ostream & stream, const SecretKey & pgp);

    // Search PGP keys for signing keys
    Packet::Key::Ptr find_signing_key(const Key & key);
}

#endif
