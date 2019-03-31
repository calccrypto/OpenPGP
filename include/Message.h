/*
Message.h
OpenPGP Message data structure (RFC 4880 sec 11.3)

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

#ifndef __OPENPGP_MESSAGE__
#define __OPENPGP_MESSAGE__

#include <list>

#include "PGP.h"
#include "Packets/Tag8.h"

namespace OpenPGP {

    // 11.3. OpenPGP Messages
    //
    //     An OpenPGP message is a packet or sequence of packets that
    //     corresponds to the following grammatical rules (comma represents
    //     sequential composition, and vertical bar separates alternatives):
    //
    //         OpenPGP Message :- Encrypted Message | Signed Message | Compressed Message | Literal Message.
    //
    //         Compressed Message :- Compressed Data Packet.
    //
    //         Literal Message :- Literal Data Packet.
    //
    //         ESK :- Public-Key Encrypted Session Key Packet | Symmetric-Key Encrypted Session Key Packet.
    //
    //         ESK Sequence :- ESK | ESK Sequence, ESK.
    //
    //         Encrypted Data :- Symmetrically Encrypted Data Packet | Symmetrically Encrypted Integrity Protected Data Packet
    //
    //         Encrypted Message :- Encrypted Data | ESK Sequence, Encrypted Data.
    //
    //         One-Pass Signed Message :- One-Pass Signature Packet, OpenPGP Message, Corresponding Signature Packet.
    //
    //         Signed Message :- Signature Packet, OpenPGP Message | One-Pass Signed Message.
    //
    //     In addition, decrypting a Symmetrically Encrypted Data packet or a
    //     Symmetrically Encrypted Integrity Protected Data packet as well as
    //     decompressing a Compressed Data packet must yield a valid OpenPGP
    //     Message.

    class Message : public PGP {
        public:
            enum Token { // Rules
                         OPENMessage,
                         ENCRYPTEDMESSAGE,
                         SIGNEDMESSAGE,
                         COMPRESSEDMESSAGE,
                         LITERALMESSAGE,
                         ESK,
                         ESKSEQUENCE,
                         ENCRYPTEDDATA,
                         ONEPASSSIGNEDMESSAGE,

                         // Symbols
                         CDP,        // Compressed Data Packet (Tag 8)
                         LDP,        // Literal Data Packet (Tag 11)
                         PKESKP,     // Public-Key Encrypted Session Key Packet (Tag 1)
                         SKESKP,     // Symmetric-Key Encrypted Session Key Packet (Tag 3)
                         SEDP,       // Symmetrically Encrypted Data Packet (Tag 9)
                         SEIPDP,     // Symmetrically Encrypted Integrity Protected Data Packet (Tag 18)
                         OPSP,       // One-Pass Signature Packet (Tag 4)
                         SP,         // Signature Packet (Tag 2)

                         NONE        // garbage value
            };

        private:
            // Reverse Rules (Reduce)
            static bool OpenMessage          (std::list <Token>::iterator it, std::list <Token> & s);
            static bool CompressedMessage    (std::list <Token>::iterator it, std::list <Token> & s);
            static bool LiteralMessage       (std::list <Token>::iterator it, std::list <Token> & s);
            static bool EncryptedSessionKey  (std::list <Token>::iterator it, std::list <Token> & s);
            static bool ESKSequence          (std::list <Token>::iterator it, std::list <Token> & s);
            static bool EncryptedData        (std::list <Token>::iterator it, std::list <Token> & s);
            static bool EncryptedMessage     (std::list <Token>::iterator it, std::list <Token> & s);
            static bool OnePassSignedMessage (std::list <Token>::iterator it, std::list <Token> & s);
            static bool SignedMessage        (std::list <Token>::iterator it, std::list <Token> & s);

            Packet::Tag8::Ptr comp;                                                                     // store tag8 data, if it exists

            bool decompress();                                                                          // decompress packet

        public:
            typedef std::shared_ptr <Message> Ptr;

            Message();
            Message(const PGP & copy);
            Message(const Message & copy);
            Message(const std::string & data);
            Message(std::istream & stream);
            ~Message();

            // Read Binary data
            void read_raw(const std::string & data);

            std::string show(const std::size_t indents = 0, const std::size_t indent_size = 4) const;   // not inherited from PGP?
            void show(HumanReadable & hr) const;                                                        // display information
            std::string raw(Status * status = nullptr, const bool check_mpi = false) const;             // write packets only
            std::string write(const Armored armor = DEFAULT, Status * status = nullptr, const bool check_mpi = false) const;

            uint8_t get_comp() const;                                                                   // get compression algorithm

            void set_comp(const uint8_t c);                                                             // set compression algorithm

            // whether or not PGP packet composition matches a OpenPGP Message grammar without constructing a new object
            static bool match(const PGP & pgp, const Token & token);

            // whether or not the packet composition of *this matches a OpenPGP Message grammar without constructing a new object
            bool match(const Token & token) const;

            // check if packet sequence of PGP data is a meaningful and correct OpenPGP Message without constructing a new object
            static bool meaningful(const PGP & pgp);

            // check if packet sequence of *this is a meaningful and correct OpenPGP Message
            // whether or not data matches Detached Signature format
            bool meaningful() const;

            PGP::Ptr clone() const;
    };

}

#endif
