/*
Tag18.h
Sym. Encrypted and Integrity Protected Data Packet

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

#ifndef __TAG18__
#define __TAG18__

#include "Packets/Packet.h"
#include "Packets/Partial.h"

namespace OpenPGP {
    namespace Packet {

        // 5.13.  Sym. Encrypted Integrity Protected Data Packet (Tag 18)
        //
        //    The Symmetrically Encrypted Integrity Protected Data packet is a
        //    variant of the Symmetrically Encrypted Data packet.  It is a new
        //    feature created for OpenPGP that addresses the problem of detecting a
        //    modification to encrypted data.  It is used in combination with a
        //    Modification Detection Code packet.
        //
        //    There is a corresponding feature in the features Signature subpacket
        //    that denotes that an implementation can properly use this packet
        //    type.  An implementation MUST support decrypting these packets and
        //    SHOULD prefer generating them to the older Symmetrically Encrypted
        //    Data packet when possible.  Since this data packet protects against
        //    modification attacks, this standard encourages its proliferation.
        //    While blanket adoption of this data packet would create
        //    interoperability problems, rapid adoption is nevertheless important.
        //    An implementation SHOULD specifically denote support for this packet,
        //    but it MAY infer it from other mechanisms.
        //
        //    For example, an implementation might infer from the use of a cipher
        //    such as Advanced Encryption Standard (AES) or Twofish that a user
        //    supports this feature.  It might place in the unhashed portion of
        //    another user's key signature a Features subpacket.  It might also
        //    present a user with an opportunity to regenerate their own self-
        //    signature with a Features subpacket.
        //
        //    This packet contains data encrypted with a symmetric-key algorithm
        //    and protected against modification by the SHA-1 hash algorithm.  When
        //    it has been decrypted, it will typically contain other packets (often
        //    a Literal Data packet or Compressed Data packet).  The last decrypted
        //    packet in this packet's payload MUST be a Modification Detection Code
        //    packet.
        //
        //    The body of this packet consists of:
        //
        //      - A one-octet version number.  The only currently defined value is
        //        1.
        //
        //      - Encrypted data, the output of the selected symmetric-key cipher
        //        operating in Cipher Feedback mode with shift amount equal to the
        //        block size of the cipher (CFB-n where n is the block size).
        //
        //    The symmetric cipher used MUST be specified in a Public-Key or
        //    Symmetric-Key Encrypted Session Key packet that precedes the
        //    Symmetrically Encrypted Data packet.  In either case, the cipher
        //    algorithm octet is prefixed to the session key before it is
        //    encrypted.
        //
        //    The data is encrypted in CFB mode, with a CFB shift size equal to the
        //    cipher's block size.  The Initial Vector (IV) is specified as all
        //    zeros.  Instead of using an IV, OpenPGP prefixes an octet string to
        //    the data before it is encrypted.  The length of the octet string
        //    equals the block size of the cipher in octets, plus two.  The first
        //    octets in the group, of length equal to the block size of the cipher,
        //    are random; the last two octets are each copies of their 2nd
        //    preceding octet.  For example, with a cipher whose block size is 128
        //    bits or 16 octets, the prefix data will contain 16 random octets,
        //    then two more octets, which are copies of the 15th and 16th octets,
        //    respectively.  Unlike the Symmetrically Encrypted Data Packet, no
        //    special CFB resynchronization is done after encrypting this prefix
        //    data.  See "OpenPGP CFB Mode" below for more details.
        //
        //    The repetition of 16 bits in the random data prefixed to the message
        //    allows the receiver to immediately check whether the session key is
        //    incorrect.
        //
        //    The plaintext of the data to be encrypted is passed through the SHA-1
        //    hash function, and the result of the hash is appended to the
        //    plaintext in a Modification Detection Code packet.  The input to the
        //    hash function includes the prefix data described above; it includes
        //    all of the plaintext, and then also includes two octets of values
        //    0xD3, 0x14.  These represent the encoding of a Modification Detection
        //    Code packet tag and length field of 20 octets.
        //
        //    The resulting hash value is stored in a Modification Detection Code
        //    (MDC) packet, which MUST use the two octet encoding just given to
        //    represent its tag and length field.  The body of the MDC packet is
        //    the 20-octet output of the SHA-1 hash.
        //
        //    The Modification Detection Code packet is appended to the plaintext
        //    and encrypted along with the plaintext using the same CFB context.
        //
        //    During decryption, the plaintext data should be hashed with SHA-1,
        //    including the prefix data as well as the packet tag and length field
        //    of the Modification Detection Code packet.  The body of the MDC
        //    packet, upon decryption, is compared with the result of the SHA-1
        //    hash.
        //
        //    Any failure of the MDC indicates that the message has been modified
        //    and MUST be treated as a security problem.  Failures include a
        //    difference in the hash values, but also the absence of an MDC packet,
        //    or an MDC packet in any position other than the end of the plaintext.
        //    Any failure SHOULD be reported to the user.
        //
        //    Note: future designs of new versions of this packet should consider
        //    rollback attacks since it will be possible for an attacker to change
        //    the version back to 1.

        class Tag18 : public Tag, public Partial {
            private:
                std::string protected_data;

                void actual_read(const std::string & data, std::string::size_type & pos, const std::string::size_type & length);
                std::string show_title() const;
                void show_contents(HumanReadable & hr) const;
                std::string actual_raw() const;
                std::string actual_write() const;
                Status actual_valid(const bool check_mpi) const;

            public:
                typedef std::shared_ptr <Packet::Tag18> Ptr;

                Tag18(const PartialBodyLength & part = NOT_PARTIAL);
                Tag18(const std::string & data);
                std::string write(Status * status = nullptr, const bool check_mpi = false) const;

                std::string get_protected_data() const;

                void set_protected_data(const std::string & p);

                Tag::Ptr clone() const;
        };
    }
}

#endif
