/*
Tag2.h
Signature Packet

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

#include "Packets/Tag2/Sub32.h"

#ifndef __TAG2__
#define __TAG2__

#include <array>
#include <string>
#include <vector>

#include "Hashes/Hashes.h"
#include "Misc/sigtypes.h"
#include "PKA/PKAs.h"
#include "Packets/Packet.h"
#include "Packets/Tag2/Subpackets.h"

namespace OpenPGP {
    namespace Packet {

        // 5.2.  Signature Packet (Tag 2)
        //
        //    A Signature packet describes a binding between some public key and
        //    some data.  The most common signatures are a signature of a file or a
        //    block of text, and a signature that is a certification of a User ID.
        //
        //    Two versions of Signature packets are defined.  Version 3 provides
        //    basic signature information, while version 4 provides an expandable
        //    format with subpackets that can specify more information about the
        //    signature.  PGP 2.6.x only accepts version 3 signatures.
        //
        //    Implementations SHOULD accept V3 signatures.  Implementations SHOULD
        //    generate V4 signatures.
        //
        //    Note that if an implementation is creating an encrypted and signed
        //    message that is encrypted to a V3 key, it is reasonable to create a
        //    V3 signature.
        //
        // 5.2.2. Version 3 Signature Packet Format
        //
        //    The body of a version 3 Signature Packet contains:
        //
        //      - One-octet version number (3).
        //
        //      - One-octet length of following hashed material. MUST be 5.
        //
        //      - One-octet signature type.
        //
        //      - Four-octet creation time.
        //
        //      - Eight-octet Key ID of signer.
        //
        //      - One-octet public-key algorithm.
        //
        //      - One-octet hash algorithm.
        //
        //      - Two-octet field holding left 16 bits of signed hash value.
        //
        //      - One or more multiprecision integers comprising the signature.
        //        This portion is algorithm specific, as described below.
        //
        //    The concatenation of the data to be signed, the signature type, and
        //    creation time from the Signature packet (5 additional octets) is
        //    hashed. The resulting hash value is used in the signature algorithm.
        //    The high 16 bits (first two octets) of the hash are included in the
        //    Signature packet to provide a quick test to reject some invalid
        //    signatures.
        //
        //    Algorithm-Specific Fields for RSA signatures:
        //
        //      - multiprecision integer (MPI) of RSA signature value m**d mod n.
        //
        //    Algorithm-Specific Fields for DSA signatures:
        //
        //      - MPI of DSA value r.
        //
        //      - MPI of DSA value s.
        //
        //    The signature calculation is based on a hash of the signed data, as
        //    described above. The details of the calculation are different for
        //    DSA signatures than for RSA signatures.
        //
        // 5.2.3. Version 4 Signature Packet Format
        //
        //    The body of a version 4 Signature packet contains:
        //
        //      - One-octet version number (4).
        //
        //      - One-octet signature type.
        //
        //      - One-octet public-key algorithm.
        //
        //      - One-octet hash algorithm.
        //
        //      - Two-octet scalar octet count for following hashed subpacket data.
        //        Note that this is the length in octets of all of the hashed
        //        subpackets; a pointer incremented by this number will skip over
        //        the hashed subpackets.
        //
        //      - Hashed subpacket data set (zero or more subpackets).
        //
        //      - Two-octet scalar octet count for the following unhashed subpacket
        //        data. Note that this is the length in octets of all of the
        //        unhashed subpackets; a pointer incremented by this number will
        //        skip over the unhashed subpackets.
        //
        //      - Unhashed subpacket data set (zero or more subpackets).
        //
        //      - Two-octet field holding the left 16 bits of the signed hash
        //        value.
        //
        //      - One or more multiprecision integers comprising the signature.
        //        This portion is algorithm specific, as described above.
        //
        //    The concatenation of the data being signed and the signature data
        //    from the version number through the hashed subpacket data (inclusive)
        //    is hashed. The resulting hash value is what is signed. The left 16
        //    bits of the hash are included in the Signature packet to provide a
        //    quick test to reject some invalid signatures.
        //
        //    There are two fields consisting of Signature subpackets. The first
        //    field is hashed with the rest of the signature data, while the second
        //    is unhashed. The second set of subpackets is not cryptographically
        //    protected by the signature and should include only advisory
        //    information.

        class Tag2 : public Tag {
            public:
                typedef std::vector <Subpacket::Tag2::Sub::Ptr> Subpackets;

            private:
                // common
                uint8_t type;
                uint8_t pka;
                uint8_t hash;
                PKA::Values mpi;
                std::string left16;        // 2 octets

                // version 3 stuff
                uint32_t time;
                std::string keyid;

                // version 4 stuff
                Subpackets hashed_subpackets;
                Subpackets unhashed_subpackets;

                // Function to read subpacket headers
                void read_subpacket(const std::string & data, std::string::size_type & pos, std::string::size_type & length);

                // Function to parse all subpackets
                void read_subpackets(const std::string & data, Subpackets & subpackets);

                void actual_read(const std::string & data, std::string::size_type & pos, const std::string::size_type & length);
                void show_contents(HumanReadable & hr) const;
                std::string actual_raw() const;
                Status actual_valid(const bool check_mpi) const;

            public:
                typedef std::shared_ptr <Packet::Tag2> Ptr;

                Tag2();
                Tag2(const Tag2 & copy);
                Tag2(const std::string & data);
                ~Tag2();

                uint8_t get_type()                              const;
                uint8_t get_pka()                               const;
                uint8_t get_hash()                              const;
                std::string get_left16()                        const;      // whatever is stored, not calculated
                PKA::Values get_mpi()                           const;

                // special functions: works differently depending on version
                std::array <uint32_t, 3> get_times()            const;      // signature creation/expiration time and key expiration time; creation time should always exist; expirations times are 0 for version 3 signatures
                std::string get_keyid()                         const;

                Subpackets get_hashed_subpackets()              const;
                Subpackets get_hashed_subpackets_clone()        const;
                Subpackets get_unhashed_subpackets()            const;
                Subpackets get_unhashed_subpackets_clone()      const;
                std::string get_up_to_hashed()                  const;     // used for signature trailer
                std::string get_without_unhashed()              const;     // used for signature type 0x50

                void set_type(const uint8_t t);
                void set_pka (const uint8_t p);
                void set_hash(const uint8_t h);
                void set_left16(const std::string & l);
                void set_mpi(const PKA::Values & m);

                // special functions: works differently depending on version
                void set_time(const uint32_t t);
                void set_keyid(const std::string & k);

                void set_hashed_subpackets(const Subpackets & h);
                void set_unhashed_subpackets(const Subpackets & u);

                std::string find_subpacket(const uint8_t sub)   const;      // find a subpacket within Signature Packet; returns raw data of last subpacket found

                Tag::Ptr clone() const;
                Tag2 & operator=(const Tag2 & tag2);
        };
    }
}

#endif
