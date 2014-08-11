/*
PGP.h
main OpenPGP data structure

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
#include "Subpackets/subpackets.h"
#include "consts.h"
#include "pgptime.h"
#include "radix64.h"

class PGP{
    protected:
        bool armored;                                                           // default true
        uint8_t ASCII_Armor;                                                    // What type of key is this
        std::vector <std::pair <std::string, std::string> > Armor_Header;       // messages in the header
        std::vector <Packet::Ptr> packets;                                      // main data

        // modifies output string so each line is no longer than MAX_LINE_SIZE long
        std::string format_string(std::string data, uint8_t line_length = MAX_LINE_LENGTH) const;

    public:
        typedef std::shared_ptr<PGP> Ptr;

        PGP();
        PGP(const PGP & copy);
        PGP(std::string & data);                                               // data fed into this constructor will be destroyed
        PGP(std::ifstream & f);
        ~PGP();

        void read(std::string & data);                                         // read key, including ASCII Armor; data is destroyed
        void read(std::ifstream & file);
        void read_raw(std::string & data);                                     // reads packet data only; data is destroyed
        std::string show() const;                                              // display key information
        std::string raw(const uint8_t header = 0) const;                       // write packets only; header is for writing default (0), old (1) or new (2) header formats
        std::string write(const uint8_t header = 0) const;                     // old or new type packet headers
        std::string output(const bool armored = true) const;                   // force write with given armor value
        
        // Accessors
        bool get_armored() const;
        uint8_t get_ASCII_Armor() const;
        std::vector <std::pair <std::string, std::string> > get_Armor_Header() const;
        std::vector <Packet::Ptr> get_packets() const;                         // get copy of all packet pointers
        std::vector <Packet::Ptr> get_packets_clone() const;                   // clone all packets

        // Modifiers
        void set_armored(const bool a);
        void set_ASCII_Armor(const uint8_t armor);
        void set_Armor_Header(const std::vector <std::pair <std::string, std::string> > & header);
        void set_packets(const std::vector <Packet::Ptr> & p);

        virtual bool meaningful() const;                                       // check if packet sequence is meaningful and correct; do not call this one

        PGP & operator=(const PGP & copy);                                     // get deep copy object
        virtual Ptr clone() const = 0;                                         // get deep copy pointer
};
#endif
