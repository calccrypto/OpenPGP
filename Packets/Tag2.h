/*
Tag2.h
Signature Packet

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

#include "../Subpackets/subpackets.h"

#ifndef __TAG2__
#define __TAG2__

#include "packet.h"

class Tag2 : public Packet{
    private:
        // common
        uint8_t type;
        uint8_t pka;
        uint8_t hash;
        std::vector <PGPMPI> mpi;
        std::string left16;        // 2 octets

        // version 3 stuff
        uint32_t time;
        std::string keyid;

        // version 4 stuff
        std::vector <Tag2Subpacket::Ptr> hashed_subpackets;
        std::vector <Tag2Subpacket::Ptr> unhashed_subpackets;

        // Function to read subpacket headers
        std::string read_subpacket(std::string & data);

        // Function to parse all subpackets
        std::vector <Tag2Subpacket::Ptr> read_subpackets(std::string & data);

    public:
        typedef std::shared_ptr <Tag2> Ptr;

        Tag2();
        Tag2(const Tag2 & copy);
        Tag2(std::string & data);
        ~Tag2();
        void read(std::string & data, const uint8_t part = 0);
        std::string show(const uint8_t indents = 0, const uint8_t indent_size = 4) const;
        std::string raw() const;

        uint8_t get_type() const;
        uint8_t get_pka() const;
        uint8_t get_hash() const;
        std::string get_left16() const; // whatever is stored, not calculated
        std::vector <PGPMPI> get_mpi() const;

        // special functions: works differently depending on version
        uint32_t get_time() const;
        std::string get_keyid() const;

        std::vector <Tag2Subpacket::Ptr> get_hashed_subpackets() const;
        std::vector <Tag2Subpacket::Ptr> get_hashed_subpackets_clone() const;
        std::vector <Tag2Subpacket::Ptr> get_unhashed_subpackets() const;
        std::vector <Tag2Subpacket::Ptr> get_unhashed_subpackets_clone() const;
        std::string get_up_to_hashed() const;                   // used for signature trailer
        std::string get_without_unhashed() const;               // used for signature type 0x50

        void set_pka(const uint8_t p);
        void set_type(const uint8_t t);
        void set_hash(const uint8_t h);
        void set_left16(const std::string & l);
        void set_mpi(const std::vector <PGPMPI> & m);

        // special functions: works differently depending on version
        void set_time(const uint32_t t);
        void set_keyid(const std::string & k);

        void set_hashed_subpackets(const std::vector <Tag2Subpacket::Ptr> & h);
        void set_unhashed_subpackets(const std::vector <Tag2Subpacket::Ptr> & u);

        std::string find_subpacket(const uint8_t sub) const;    // find a subpacket within Signature Packet; returns raw data of last subpacket found

        Packet::Ptr clone() const;
        Tag2 & operator =(const Tag2 & copy);
};
#endif
