/*
PGP.h
main OpenPGP data structure

Copyright (c) 2013 Jason Lee

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
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>
#include <utility>

#include "../common/includes.h"
#include "../Packets/packets.h"
#include "../Subpackets/subpackets.h"
#include "../consts.h"
#include "../pgptime.h"
#include "../radix64.h"

#ifndef __PGP_BASE__
#define __PGP_BASE__
class PGP{
    protected:
        bool armored;
        uint8_t ASCII_Armor;                                                    // What type of key is this
        std::vector <std::pair <std::string, std::string> > Armor_Header;       // messages in the header
        std::vector <Packet*> packets;                                          // main data

        // modifies output string so each line is no longer than MAX_LINE_SIZE long
        std::string format_string(std::string data, uint8_t line_length = MAX_LINE_LENGTH);

    public:
        PGP();
        PGP(const PGP & pgp);
        PGP(std::string & data);                                                // data fed into this constructor will be destroyed
        PGP(std::ifstream & f);
        ~PGP();

        void read(std::string & data, int8_t type = -1);
        void read(std::ifstream & file, int8_t type = -1);
        void read_raw(std::string & data);                                      // reads packet data only
        std::string show();                                                     // display key information
        std::string raw();                                                      // write packets only
        std::string write();                                                    // output with ASCII Armor and converted to Radix64

        bool get_armored();
        uint8_t get_ASCII_Armor();
        std::vector <std::pair <std::string, std::string> > get_Armor_Header();
        std::vector <Packet *> get_packets();                                   // get copy of all packet pointers
        std::vector <Packet *> get_packets_clone();                             // clone all packets

        void set_armored(const bool a);
        void set_ASCII_Armor(const uint8_t armor);
        void set_Armor_Header(const std::vector <std::pair <std::string, std::string> > & header);
        void set_packets(const std::vector <Packet *> & p);

        std::string keyid();                                                // keyid that is searched for on keyservers
        std::string list_keys();                                            // output is copied from gpg --list-keys; only makes sense for keys; other types output empty strings

        PGP operator=(const PGP & pgp);                                     // get deep copy object
        PGP * clone();                                                      // get deep copy pointer
};

// Display key id of primary key
std::ostream & operator<<(std::ostream & stream, PGP & pgp);
#endif
