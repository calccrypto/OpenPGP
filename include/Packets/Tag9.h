/*
Tag9.h
Symmetrically Encrypted Data Packet

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

#ifndef __TAG9__
#define __TAG9__

#include "Packets/Packet.h"
#include "Packets/Partial.h"

namespace OpenPGP {
    namespace Packet {

        // 5.7.  Symmetrically Encrypted Data Packet (Tag 9)
        //
        //    The Symmetrically Encrypted Data packet contains data encrypted with
        //    a symmetric-key algorithm.  When it has been decrypted, it contains
        //    other packets (usually a literal data packet or compressed data
        //    packet, but in theory other Symmetrically Encrypted Data packets or
        //    sequences of packets that form whole OpenPGP messages).
        //
        //    The body of this packet consists of:
        //
        //      - Encrypted data, the output of the selected symmetric-key cipher
        //        operating in OpenPGP's variant of Cipher Feedback (CFB) mode.
        //
        //    The symmetric cipher used may be specified in a Public-Key or
        //    Symmetric-Key Encrypted Session Key packet that precedes the
        //    Symmetrically Encrypted Data packet.  In that case, the cipher
        //    algorithm octet is prefixed to the session key before it is
        //    encrypted.  If no packets of these types precede the encrypted data,
        //    the IDEA algorithm is used with the session key calculated as the MD5
        //    hash of the passphrase, though this use is deprecated.
        //
        //    The data is encrypted in CFB mode, with a CFB shift size equal to the
        //    cipher's block size.  The Initial Vector (IV) is specified as all
        //    zeros.  Instead of using an IV, OpenPGP prefixes a string of length
        //    equal to the block size of the cipher plus two to the data before it
        //    is encrypted.  The first block-size octets (for example, 8 octets for
        //    a 64-bit block length) are random, and the following two octets are
        //    copies of the last two octets of the IV.  For example, in an 8-octet
        //    block, octet 9 is a repeat of octet 7, and octet 10 is a repeat of
        //    octet 8.  In a cipher of length 16, octet 17 is a repeat of octet 15
        //    and octet 18 is a repeat of octet 16.  As a pedantic clarification,
        //    in both these examples, we consider the first octet to be numbered 1.
        //
        //    After encrypting the first block-size-plus-two octets, the CFB state
        //    is resynchronized.  The last block-size octets of ciphertext are
        //    passed through the cipher and the block boundary is reset.
        //
        //    The repetition of 16 bits in the random data prefixed to the message
        //    allows the receiver to immediately check whether the session key is
        //    incorrect.  See the "Security Considerations" section for hints on
        //    the proper use of this "quick check".

        class Tag9 : public Tag, public Partial {
            private:
                std::string encrypted_data;

                void actual_read(const std::string & data, std::string::size_type & pos, const std::string::size_type & length);
                std::string show_title() const;
                void show_contents(HumanReadable & hr) const;
                std::string actual_raw() const;
                std::string actual_write() const;
                Status actual_valid(const bool check_mpi) const;

            public:
                typedef std::shared_ptr <Packet::Tag9> Ptr;

                Tag9(const PartialBodyLength &part = NOT_PARTIAL);
                Tag9(const std::string & data);
                std::string write(Status * status = nullptr, const bool check_mpi = false) const;

                Tag::Ptr clone() const;

                std::string get_encrypted_data() const;

                void set_encrypted_data(const std::string & e);
        };
    }
}

#endif
