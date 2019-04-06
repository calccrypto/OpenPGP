/*
PGP.h
main OpenPGP data structure

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

#ifndef __OPENPGP_BASE__
#define __OPENPGP_BASE__

#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

#include "Misc/radix64.h"
#include "Packets/Packets.h"
#include "common/HumanReadable.h"

namespace OpenPGP {
    class PGP {
        public:
            typedef uint8_t Type_t;
            static const Type_t UNKNOWN;                    // Default value
            static const Type_t MESSAGE;                    // Used for signed, encrypted, or compressed files.
            static const Type_t PUBLIC_KEY_BLOCK;           // Used for armoring public keys.
            static const Type_t PRIVATE_KEY_BLOCK;          // Used for armoring private keys.
            static const Type_t MESSAGE_PART_XY;            // Used for multi-part messages, where the armor is split amongst Y parts, and this is the Xth part out of Y.
            static const Type_t MESSAGE_PART_X;             // Used for multi-part messages, where this is the Xth part of an unspecified number of parts. Requires the MESSAGE-ID Armor Header to be used.
            static const Type_t SIGNATURE;                  // Used for detached signatures, OpenPGP/MIME signatures, and cleartext signatures. Note that PGP 2.x uses BEGIN PGP MESSAGE for detached signatures.
            static const Type_t SIGNED_MESSAGE;             // Used for cleartext signatures; Bad PGP type.

            static const std::string ASCII_Armor_5_Dashes;  // "-----";
            static const std::string ASCII_Armor_Begin;     // "-----BEGIN PGP ";
            static const std::string ASCII_Armor_Header[];  // ASCII data at beginning and end of OpenPGP packet
            static const std::string ASCII_Armor_Key[];     // ASCII descriptor of OpenPGP packet
            static const std::string ASCII_Armor_End;       // "-----END PGP ";

            // used for write function
            enum Armored {
                DEFAULT,                                    // use value stored in PGP::armored
                YES,                                        // write ASCII version
                NO,                                         // write binary version
            };

            typedef std::pair <std::string, std::string> Armor_Key;
            typedef std::vector <Armor_Key> Armor_Keys;
            typedef std::vector <Packet::Tag::Ptr> Packets;

        protected:
            bool armored;                                   // default true
            Type_t type;                                    // what type of key is this
            Armor_Keys keys;                                // key-value pairs in the ASCII header
            Packets packets;                                // main data

            // reads the data starting at pos, and gets the ctb, format, and tag
            // pos is shifted up by 1
            uint8_t read_packet_header(const std::string & data, std::string::size_type & pos, uint8_t & ctb, Packet::HeaderFormat & format, uint8_t & tag) const;

            // reads the length of the packet data and extracts the start and length of the packet data
            // if partial returns Packet::PARTIAL, the partial_data variable should be used instead of data
            Packet::PartialBodyLength read_packet_unformatted(const Packet::HeaderFormat format, const uint8_t ctb, const std::string & data, std::string::size_type & pos, std::string::size_type & packet_start, std::string::size_type & packet_length, std::string & partial_data) const;

            // parses raw packet data
            Packet::Tag::Ptr read_packet_raw(const std::string & data, std::string::size_type & pos, const std::string::size_type & length, const uint8_t tag, const Packet::HeaderFormat format, const Packet::PartialBodyLength & partial) const;

            // parse packet with header; wrapper for read_packet_header and read_packet_unformatted
            Packet::Tag::Ptr read_packet(const std::string & data, std::string::size_type & pos) const;

            // modifies output string so each line is no longer than MAX_LINE_SIZE long
            std::string format_string(const std::string & data, const uint8_t line_length = MAX_LINE_LENGTH) const;

        public:
            typedef std::shared_ptr <PGP> Ptr;

            PGP();
            PGP(const PGP & copy);                          // clone another PGP instance
            PGP(const std::string & data);
            PGP(std::istream & stream);
            virtual ~PGP();

            // Read ASCII Header + Base64 data
            // all of the input will be considered valid for processing
            void read(const std::string & data);
            void read(std::istream & stream);

            // Read Binary data
            // all of the input will be considered valid for processing
            virtual void read_raw(const std::string & data);
            void read_raw(std::istream & stream);

            // Show the contents in a human readable format
            std::string show(const std::size_t indents = 0, const std::size_t indent_size = 4) const;   // quick print
            virtual void show(HumanReadable & hr) const;                                                // buffered print

            // Write data out
            virtual std::string raw(Status * status = nullptr, const bool check_mpi = false) const;     // write packets only
            virtual std::string write(const Armored armor = DEFAULT, Status * status = nullptr, const bool check_mpi = false) const;

            // Accessors
            bool get_armored()              const;
            Type_t get_type()               const;
            const Armor_Keys & get_keys()   const;
            const Packets & get_packets()   const;          // get copy of all packet pointers (for looping through packets)
            Packets get_packets_clone()     const;          // clone all packets (for modifying packets)

            // Modifiers
            void set_armored(const bool a);
            void set_type(const Type_t t);
            void set_keys(const Armor_Keys & keys);
            void set_packets(const Packets & p);            // copies the the input packet pointers
            void set_packets_clone(const Packets & p);      // clones the input packets

            virtual bool operator==(const PGP & rhs) const;

            PGP & operator=(const PGP & copy);              // get deep copy object
            virtual Ptr clone() const;                      // get deep copy pointer
    };

    std::ostream & operator<<(std::ostream & stream, const PGP & pgp);
}

#endif
