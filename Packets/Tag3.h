/*
Tag3.h
Symmetric-Key Encrypted Session Key Packet

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

#ifndef __TAG3__
#define __TAG3__

#include <string>

#include "../Misc/cfb.h"
#include "../Misc/s2k.h"
#include "Packet.h"

namespace OpenPGP {
    namespace Packet {

        // 5.3.  Symmetric-Key Encrypted Session Key Packets (Tag 3)
        //
        //    The Symmetric-Key Encrypted Session Key packet holds the
        //    symmetric-key encryption of a session key used to encrypt a message.
        //    Zero or more Public-Key Encrypted Session Key packets and/or
        //    Symmetric-Key Encrypted Session Key packets may precede a
        //    Symmetrically Encrypted Data packet that holds an encrypted message.
        //    The message is encrypted with a session key, and the session key is
        //    itself encrypted and stored in the Encrypted Session Key packet or
        //    the Symmetric-Key Encrypted Session Key packet.
        //
        //    If the Symmetrically Encrypted Data packet is preceded by one or
        //    more Symmetric-Key Encrypted Session Key packets, each specifies a
        //    passphrase that may be used to decrypt the message.  This allows a
        //    message to be encrypted to a number of public keys, and also to one
        //    or more passphrases.  This packet type is new and is not generated
        //    by PGP 2.x or PGP 5.0.
        //
        //    The body of this packet consists of:
        //
        //      - A one-octet version number.  The only currently defined version
        //        is 4.
        //
        //      - A one-octet number describing the symmetric algorithm used.
        //
        //      - A string-to-key (S2K) specifier, length as defined above.
        //
        //      - Optionally, the encrypted session key itself, which is decrypted
        //        with the string-to-key object.
        //
        //    If the encrypted session key is not present (which can be detected
        //    on the basis of packet length and S2K specifier size), then the S2K
        //    algorithm applied to the passphrase produces the session key for
        //    decrypting the file, using the symmetric cipher algorithm from the
        //    Symmetric-Key Encrypted Session Key packet.
        //
        //    If the encrypted session key is present, the result of applying the
        //    S2K algorithm to the passphrase is used to decrypt just that
        //    encrypted session key field, using CFB mode with an IV of all zeros.
        //    The decryption result consists of a one-octet algorithm identifier
        //    that specifies the symmetric-key encryption algorithm used to
        //    encrypt the following Symmetrically Encrypted Data packet, followed
        //    by the session key octets themselves.
        //
        //    Note: because an all-zero IV is used for this decryption, the S2K
        //    specifier MUST use a salt value, either a Salted S2K or an
        //    Iterated-Salted S2K.  The salt value will ensure that the decryption
        //    key is not repeated even if the passphrase is reused.

        class Tag3 : public Tag {
            private:
                uint8_t sym;
                S2K::S2K::Ptr s2k;
                std::shared_ptr <std::string> esk; // encrypted session key

            public:
                typedef std::shared_ptr <Packet::Tag3> Ptr;

                Tag3();
                Tag3(const Tag3 & copy);
                Tag3(const std::string & data);
                ~Tag3();
                void read(const std::string & data);
                std::string show(const std::size_t indents = 0, const std::size_t indent_size = 4) const;
                std::string raw() const;

                uint8_t get_sym() const;
                S2K::S2K::Ptr get_s2k() const;
                S2K::S2K::Ptr get_s2k_clone() const;
                std::shared_ptr <std::string> get_esk() const;
                std::shared_ptr <std::string> get_esk_clone() const;
                std::string get_session_key(const std::string & pass) const;

                void set_sym(const uint8_t s);
                void set_s2k(const S2K::S2K::Ptr & s);
                void set_esk(std::string * s);
                void set_esk(const std::string & s);
                void set_session_key(const std::string & pass, const std::string & sk = "");    // passing in empty sk will erase esk

                Tag::Ptr clone() const;
                Tag3 & operator=(const Tag3 & tag3);
        };
    }
}

#endif
