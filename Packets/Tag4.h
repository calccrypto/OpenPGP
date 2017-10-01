/*
Tag4.h
One-Pass Signature Packet

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

#ifndef __TAG4__
#define __TAG4__

#include <string>

#include "../Hashes/Hashes.h"
#include "../Misc/sigtypes.h"
#include "../PKA/PKAs.h"
#include "Packet.h"

namespace OpenPGP {
    namespace Packet {

        // 5.4.  One-Pass Signature Packets (Tag 4)
        //
        //    The One-Pass Signature packet precedes the signed data and contains
        //    enough information to allow the receiver to begin calculating any
        //    hashes needed to verify the signature.  It allows the Signature
        //    packet to be placed at the end of the message, so that the signer
        //    can compute the entire signed message in one pass.
        //
        //    A One-Pass Signature does not interoperate with PGP 2.6.x or
        //    earlier.
        //
        //    The body of this packet consists of:
        //
        //      - A one-octet version number.  The current version is 3.
        //
        //      - A one-octet signature type.  Signature types are described in
        //        Section 5.2.1.
        //
        //      - A one-octet number describing the hash algorithm used.
        //
        //      - A one-octet number describing the public-key algorithm used.
        //
        //      - An eight-octet number holding the Key ID of the signing key.
        //
        //      - A one-octet number holding a flag showing whether the signature
        //        is nested.  A zero value indicates that the next packet is
        //        another One-Pass Signature packet that describes another
        //        signature to be applied to the same message data.
        //
        //    Note that if a message contains more than one one-pass signature,
        //    then the Signature packets bracket the message; that is, the first
        //    Signature packet after the message corresponds to the last one-pass
        //    packet and the final Signature packet corresponds to the first
        //    one-pass packet.

        class Tag4 : public Tag {
            private:
                uint8_t type;
                uint8_t hash;
                uint8_t pka;
                std::string keyid; // 8 octets
                uint8_t nested;    // A zero value indicates that the next packet is another One-Pass Signature packet that describes another signature to be applied to the same message data.

            public:
                typedef std::shared_ptr <Packet::Tag4> Ptr;

                Tag4();
                Tag4(const Tag4 & copy);
                Tag4(const std::string & data);
                void read(const std::string & data);
                std::string show(const std::size_t indents = 0, const std::size_t indent_size = 4) const;
                std::string raw() const;

                uint8_t get_type() const;
                uint8_t get_hash() const;
                uint8_t get_pka() const;
                std::string get_keyid() const;
                uint8_t get_nested() const;

                void set_type(const uint8_t t);
                void set_hash(const uint8_t h);
                void set_pka(const uint8_t p);
                void set_keyid(const std::string & k);
                void set_nested(const uint8_t n);

                Tag::Ptr clone() const;
        };
    }
}

#endif
