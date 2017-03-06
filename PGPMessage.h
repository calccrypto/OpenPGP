/*
PGPMessage.h
OpenPGP Message data structure (RFC 4880 sec 11.3)

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

#ifndef __PGP_MESSAGE__
#define __PGP_MESSAGE__

#include "PGP.h"

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

class PGPMessage : public PGP {
    private:
        Tag8::Ptr comp;                                                                     // store tag8 data, if it exists

        void decompress();                                                                  // decompress packet

    public:
        typedef std::shared_ptr <PGPMessage> Ptr;

        PGPMessage();
        PGPMessage(const PGP & copy);
        PGPMessage(const PGPMessage & copy);
        PGPMessage(const std::string & data);
        PGPMessage(std::istream & stream);
        ~PGPMessage();

        std::string show(const uint8_t indents = 0, const uint8_t indent_size = 4) const;   // display information; indents is used to tab the output if desired
        std::string raw(const uint8_t header = 0) const;                                    // write packets only; header is for writing default (0), old (1) or new (2) header formats
        std::string write(const uint8_t armor = 0, const uint8_t header = 0) const;         // armor: use default = 0, no armor = 1, armored = 2; header: same as raw()

        uint8_t get_comp() const;                                                           // get compression algorithm

        void set_comp(const uint8_t c);                                                     // set compression algorithm

        // check if packet composition matches a OpenPGP Message grammar rule
        bool match(const PGP::Message::Token & token, std::string & error) const;
        bool match(const PGP::Message::Token & token) const;

        // check if packet sequence is a meaningful and correct OpenPGP Message
        bool meaningful(std::string & error)                               const;
        using PGP::meaningful;

        PGP::Ptr clone() const;
};

#endif