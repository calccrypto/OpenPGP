#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

#include <gmpxx.h>

#include "common/includes.h"
#include "Packets/packets.h"
#include "Subpackets/subpackets.h"
#include "consts.h"
#include "pgptime.h"
#include "radix64.h"

#ifndef __PGP_STRUCTURES__
#define __PGP_STRUCTURES__

#define MAX_LINE_LENGTH     64          // max is 76 for OpenPGP

class PGP{
    private:
        bool armored;
        uint8_t ASCII_Armor;
        std::vector <std::pair <std::string, std::string> > Armor_Header;
        std::vector <Packet*> packets;

        // modifies output string so each line is no longer than MAX_LINE_SIZE long
        std::string format_string(std::string data, uint8_t line_length = MAX_LINE_LENGTH);

    public:
        PGP();
        PGP(std::string & data);
        PGP(std::ifstream & f);
        PGP(const PGP & pgp);
        ~PGP();

        void read(std::string & data);
        void read(std::ifstream & file);
        void read_raw(std::string & data);          // reads packet data only
        std::string show();                         // display key information
        std::string raw();                          // write packets only
        std::string write();                        // output with ASCII Armor and converted to Radix64

        PGP copy();
        PGP * clone();

        uint8_t get_ASCII_Armor();
        std::vector <std::pair <std::string, std::string> > get_Armor_Header();
        std::vector <Packet *> get_packets_pointers();
        std::vector <Packet *> get_packets_copy();

        void set_ASCII_Armor(uint8_t armor);
        void set_Armor_Header(const std::vector <std::pair <std::string, std::string> > header);
        void set_packets(std::vector <Packet *> p);

        std::string keyid();                    // keyid that is searched for on keyservers
        std::string list_keys();                // output is copied from gpg --list-keys; only makes sense for keys; other types output empty strings
};

// Display key id of primary key
std::ostream & operator<<(std::ostream & stream, PGP & pgp);

class PGPMessage{
    private:
        uint8_t ASCII_Armor;
        std::vector <std::pair <std::string, std::string> > Armor_Header;
        std::string message;
        PGP key;

    public:
        PGPMessage();
        PGPMessage(std::string & data);
        PGPMessage(std::ifstream & f);
        ~PGPMessage();

        void read(std::string & data);
        void read(std::ifstream & file);
        std::string show();
        std::string write();

        uint8_t get_ASCII_Armor();
        std::vector <std::pair <std::string, std::string> > get_Armor_Header();
        std::string get_message();
        PGP get_key();

        void set_ASCII_Armor(uint8_t a);
        void set_Armor_Heder(std::vector <std::pair <std::string, std::string> > & a);
        void set_message(std::string & data);
        void set_key(PGP & k);
};
#endif
