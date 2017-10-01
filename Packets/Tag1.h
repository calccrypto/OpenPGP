/*
Tag1.h
Public-Key Encrypted Session Key Packet

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

#ifndef __TAG1__
#define __TAG1__

#include "../PKA/PKAs.h"
#include "Packet.h"

namespace OpenPGP {
    namespace Packet {

        // 5.1.  Public-Key Encrypted Session Key Packets (Tag 1)
        //
        //    A Public-Key Encrypted Session Key packet holds the session key used
        //    to encrypt a message.  Zero or more Public-Key Encrypted Session Key
        //    packets and/or Symmetric-Key Encrypted Session Key packets may
        //    precede a Symmetrically Encrypted Data Packet, which holds an
        //    encrypted message.  The message is encrypted with the session key,
        //    and the session key is itself encrypted and stored in the Encrypted
        //    Session Key packet(s).  The Symmetrically Encrypted Data Packet is
        //    preceded by one Public-Key Encrypted Session Key packet for each
        //    OpenPGP key to which the message is encrypted.  The recipient of the
        //    message finds a session key that is encrypted to their public key,
        //    decrypts the session key, and then uses the session key to decrypt
        //    the message.
        //
        //    The body of this packet consists of:
        //
        //      - A one-octet number giving the version number of the packet type.
        //        The currently defined value for packet version is 3.
        //
        //      - An eight-octet number that gives the Key ID of the public key to
        //        which the session key is encrypted.  If the session key is
        //        encrypted to a subkey, then the Key ID of this subkey is used
        //        here instead of the Key ID of the primary key.
        //
        //      - A one-octet number giving the public-key algorithm used.
        //
        //      - A string of octets that is the encrypted session key.  This
        //        string takes up the remainder of the packet, and its contents are
        //        dependent on the public-key algorithm used.
        //
        //    Algorithm Specific Fields for RSA encryption
        //
        //      - multiprecision integer (MPI) of RSA encrypted value m**e mod n.
        //
        //    Algorithm Specific Fields for ELGAMAL encryption:
        //
        //      - MPI of ELGAMAL (Diffie-Hellman) value g**k mod p.
        //
        //      - MPI of ELGAMAL (Diffie-Hellman) value m * y**k mod p.
        //
        //    The value "m" in the above formulas is derived from the session key
        //    as follows.  First, the session key is prefixed with a one-octet
        //    algorithm identifier that specifies the symmetric encryption
        //    algorithm used to encrypt the following Symmetrically Encrypted Data
        //    Packet.  Then a two-octet checksum is appended, which is equal to the
        //    sum of the preceding session key octets, not including the algorithm
        //    identifier, modulo 65536.  This value is then encoded as described in
        //    PKCS#1 block encoding EME-PKCS1-v1_5 in Section 7.2.1 of [RFC3447] to
        //    form the "m" value used in the formulas above.  See Section 13.1 of
        //    this document for notes on OpenPGP's use of PKCS#1.
        //
        //    Note that when an implementation forms several PKESKs with one
        //    session key, forming a message that can be decrypted by several keys,
        //    the implementation MUST make a new PKCS#1 encoding for each key.
        //
        //    An implementation MAY accept or use a Key ID of zero as a "wild card"
        //    or "speculative" Key ID.  In this case, the receiving implementation
        //    would try all available private keys, checking for a valid decrypted
        //    session key.  This format helps reduce traffic analysis of messages.

        class Tag1 : public Tag {
            private:
                std::string keyid;      // 8 octets
                uint8_t pka;
                PKA::Values mpi;        // algorithm specific fields

            public:
                typedef std::shared_ptr <Packet::Tag1> Ptr;

                Tag1();
                Tag1(const Tag1 & copy);
                Tag1(const std::string & data);
                void read(const std::string & data);
                std::string show(const std::size_t indents = 0, const std::size_t indent_size = 4) const;
                std::string raw() const;

                std::string get_keyid() const;
                uint8_t get_pka() const;
                PKA::Values get_mpi() const;

                void set_keyid(const std::string & k);
                void set_pka(const uint8_t p);
                void set_mpi(const PKA::Values & m);

                Tag::Ptr clone() const;
        };
    }
}

#endif
