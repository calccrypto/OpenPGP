/*
PGPMessage.h
OpenPGP Message data structure (RFC 4880 sec 11.3)

Copyright (c) 2013, 2014 Jason Lee

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

#include <list>

#include "PGP.h"

class PGPMessage : public PGP {
    private:
        /*
        11.3. OpenPGP Messages

            An OpenPGP message is a packet or sequence of packets that
            corresponds to the following grammatical rules (comma represents
            sequential composition, and vertical bar separates alternatives):

                OpenPGP Message :- Encrypted Message | Signed Message | Compressed Message | Literal Message.

                Compressed Message :- Compressed Data Packet.

                Literal Message :- Literal Data Packet.

                ESK :- Public-Key Encrypted Session Key Packet | Symmetric-Key Encrypted Session Key Packet.

                ESK Sequence :- ESK | ESK Sequence, ESK.

                Encrypted Data :- Symmetrically Encrypted Data Packet | Symmetrically Encrypted Integrity Protected Data Packet

                Encrypted Message :- Encrypted Data | ESK Sequence, Encrypted Data.

                One-Pass Signed Message :- One-Pass Signature Packet, OpenPGP Message, Corresponding Signature Packet.

                Signed Message :- Signature Packet, OpenPGP Message | One-Pass Signed Message.

            In addition, decrypting a Symmetrically Encrypted Data packet or a
            Symmetrically Encrypted Integrity Protected Data packet as well as
            decompressing a Compressed Data packet must yield a valid OpenPGP
            Message.
        */

        enum Token { // Rules
                     OPENPGPMESSAGE,
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
                     SP          // Signature Packet (Tag 2)
                };

        // Reverse Rules
        const bool OpenPGPMessage(std::list <Token>::iterator it) const;
        const bool CompressedMessage(std::list <Token>::iterator it) const;
        const bool LiteralMessage(std::list <Token>::iterator it) const;
        const bool EncryptedSessionKey(std::list <Token>::iterator it) const;
        const bool ESKSequence(std::list <Token>::iterator it) const;
        const bool EncryptedData(std::list <Token>::iterator it) const;
        const bool EncryptedMessage(std::list <Token>::iterator it) const;
        const bool OnePassSignedMessage(std::list <Token>::iterator it) const;
        const bool SignedMessage(std::list <Token>::iterator it) const;

    public:
        typedef std::shared_ptr <PGPMessage> Ptr;
    
        PGPMessage();
        PGPMessage(const PGPMessage & copy);
        PGPMessage(std::string & data);
        PGPMessage(std::ifstream & f);
        ~PGPMessage();

        PGP::Ptr clone() const;
        
        bool meaningful() const;
};

#endif