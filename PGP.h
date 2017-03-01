/*
PGP.h
main OpenPGP data structure

Copyright (c) 2013 - 2017 Jason Lee @ calccrypto@gmail.com

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

#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <vector>
#include <utility>

#include "common/includes.h"
#include "Packets/packets.h"
#include "consts.h"
#include "pgptime.h"
#include "radix64.h"

class PGP{
    public:
        typedef std::vector <std::pair <std::string, std::string> > Armor_Header_T;
        typedef std::vector <Packet::Ptr> Packets_T;

    protected:
        bool armored;                               // default true
        uint8_t ASCII_Armor;                        // what type of key is this
        Armor_Header_T Armor_Header;                // messages in the header
        Packets_T packets;                           // main data

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
        PGP(const PGP & copy);                      // clone another PGP instance
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
        bool get_armored() const;
        uint8_t get_ASCII_Armor() const;
        Armor_Header_T get_Armor_Header() const;
        Packets_T get_packets() const;               // get copy of all packet pointers (for looping through packets)
        Packets_T get_packets_clone() const;         // clone all packets (for modifying packets)

        // Modifiers
        void set_armored(const bool a);
        void set_ASCII_Armor(const uint8_t armor);
        void set_Armor_Header(const Armor_Header_T & header);
        void set_packets(const Packets_T & p);       // clones the input packets

        virtual bool meaningful() const = 0;        // check if packet sequence is meaningful and correct

        PGP & operator=(const PGP & copy);          // get deep copy object
        virtual Ptr clone() const = 0;              // get deep copy pointer
};
#endif
