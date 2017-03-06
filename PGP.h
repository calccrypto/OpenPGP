/*
PGP.h
main OpenPGP data structure

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

#ifndef __PGP_BASE__
#define __PGP_BASE__

#include <list>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <utility>

#include "common/includes.h"
#include "Packets/packets.h"
#include "pgptime.h"
#include "radix64.h"

class PGP{
    public:
        typedef uint8_t Type_t;

        struct Type{
            static const Type_t UNKNOWN;                // Default value
            static const Type_t MESSAGE;                // Used for signed, encrypted, or compressed files.
            static const Type_t PUBLIC_KEY_BLOCK;       // Used for armoring public keys.
            static const Type_t PRIVATE_KEY_BLOCK;      // Used for armoring private keys.
            static const Type_t MESSAGE_PART_XY;        // Used for multi-part messages, where the armor is split amongst Y parts, and this is the Xth part out of Y.
            static const Type_t MESSAGE_PART_X;         // Used for multi-part messages, where this is the Xth part of an unspecified number of parts. Requires the MESSAGE-ID Armor Header to be used.
            static const Type_t SIGNATURE;              // Used for detached signatures, OpenPGP/MIME signatures, and cleartext signatures. Note that PGP 2.x uses BEGIN PGP MESSAGE for detached signatures.

            static const Type_t SIGNED_MESSAGE;         // Used for cleartext signatures; header not really part of RFC 4880.
            static const Type_t KEY_BLOCK;              // Used to check if type is PUBLIC_KEY_BLOCK or PRIVATE_KEY_BLOCK
        };

        static const std::string ASCII_Armor_Header[];  // ASCII data at beginning and end of OpenPGP packet
        static const std::string ASCII_Armor_Key[];     // ASCII descriptor of OpenPGP packet

        typedef std::pair <std::string, std::string> Armor_Key;
        typedef std::vector <Armor_Key> Armor_Keys;
        typedef std::vector <Packet::Ptr> Packets;

    protected:
        bool armored;                                   // default true
        Type_t type;                                    // what type of key is this
        Armor_Keys keys;                                // key-value pairs in the ASCII header
        Packets packets;                                // main data

        // calculates the length of a partial body
        unsigned int partialBodyLen(uint8_t first_octet) const;

        // figures out where packet data starts and updates pos arguments
        // length, tag, format and partial arguments also filled
        uint8_t read_packet_header(const std::string & data, std::string::size_type & pos, std::string::size_type & length, uint8_t & tag, bool & format, uint8_t & partial) const;

        // parses raw packet data
        Packet::Ptr read_packet_raw(const bool format, const uint8_t tag, uint8_t & partial, const std::string & data, std::string::size_type & pos, const std::string::size_type & length) const;

        // parse packet with header; wrapper for read_packet_header and read_packet_raw
        // partial should be initialized with 0
        Packet::Ptr read_packet(const std::string & data, std::string::size_type & pos, uint8_t & partial) const;

        // modifies output string so each line is no longer than MAX_LINE_SIZE long
        std::string format_string(std::string data, uint8_t line_length = MAX_LINE_LENGTH) const;

    public:
        typedef std::shared_ptr <PGP> Ptr;

        PGP();
        PGP(const PGP & copy);                  // clone another PGP instance
        PGP(const std::string & data);
        PGP(std::istream & stream);
        ~PGP();

        // Read ASCII Header + Base64 data
        void read(const std::string & data);
        void read(std::istream & stream);

        // Read Binary data
        void read_raw(const std::string & data);
        void read_raw(std::istream & stream);

        virtual std::string show(const uint8_t indents = 0, const uint8_t indent_size = 4) const;   // display information; indents is used to tab the output if desired
        virtual std::string raw(const uint8_t header = 0) const;                                    // write packets only; header is for writing default (0), old (1) or new (2) header formats
        virtual std::string write(const uint8_t armor = 0, const uint8_t header = 0) const;         // armor: use default = 0, no armor = 1, armored = 2; header: same as raw()

        // Accessors
        bool get_armored()            const;
        Type_t get_type()             const;
        const Armor_Keys & get_keys() const;
        const Packets & get_packets() const;    // get copy of all packet pointers (for looping through packets)
        Packets get_packets_clone()   const;    // clone all packets (for modifying packets)

        // Modifiers
        void set_armored(const bool a);
        void set_type(const Type_t header);
        void set_keys(const Armor_Keys & keys);
        void set_packets(const Packets & p);    // clones the input packets

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
        struct Message{
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
                         SP,         // Signature Packet (Tag 2)

                         NONE        // garbage value
                    };

            typedef Token Type;

            // Reverse Rules (Reduce)
            static bool OpenPGPMessage       (std::list <Token>::iterator it, std::list <Token> & s);
            static bool CompressedMessage    (std::list <Token>::iterator it, std::list <Token> & s);
            static bool LiteralMessage       (std::list <Token>::iterator it, std::list <Token> & s);
            static bool EncryptedSessionKey  (std::list <Token>::iterator it, std::list <Token> & s);
            static bool ESKSequence          (std::list <Token>::iterator it, std::list <Token> & s);
            static bool EncryptedData        (std::list <Token>::iterator it, std::list <Token> & s);
            static bool EncryptedMessage     (std::list <Token>::iterator it, std::list <Token> & s);
            static bool OnePassSignedMessage (std::list <Token>::iterator it, std::list <Token> & s);
            static bool SignedMessage        (std::list <Token>::iterator it, std::list <Token> & s);
        };

        bool meaningful_MESSAGE(const Message::Token & token, std::string & error) const;
        bool meaningful_KEY_BLOCK(const Type_t & t, std::string & error)           const;
        bool meaningful_PUBLIC_KEY_BLOCK(std::string & error)                      const;
        bool meaningful_PRIVATE_KEY_BLOCK(std::string & error)                     const;
        bool meaningful_MESSAGE_PART_XY(std::string & error)                       const;
        bool meaningful_MESSAGE_PART_X(std::string & error)                        const;
        bool meaningful_SIGNATURE(std::string & error)                             const;

        // check if packet sequence is meaningful and correct for a given type
        bool meaningful(const Type_t & t, std::string & error)                     const;
        bool meaningful(const Type_t & t)                                          const;

        // check if packet sequence is meaningful and correct with stored type
        // allow for child classes to check their specific types
        virtual bool meaningful(std::string & error)                               const;
        virtual bool meaningful()                                                  const;

        PGP & operator=(const PGP & copy);          // get deep copy object
        virtual Ptr clone() const;                  // get deep copy pointer
};

#endif
