/*
packet.h
Base class for OpenPGP packet types to inherit from

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

#ifndef __PACKET__
#define __PACKET__

#include <cstdlib>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "../common/includes.h"
#include "../Hashes/Hashes.h"
#include "../consts.h"
#include "../mpi.h"
#include "../pgptime.h"

class Packet{
    protected:
        uint8_t tag;        // RFC 4880 sec 4.3
        uint8_t version;
        bool format;        // OLD or NEW; only used when "show"ing. "write" will write whatever it set; default is NEW
        unsigned int size;  // This value is only correct when the packet was generated with the read() function
        uint8_t partial;    // 0-3; 0 = not partial, 1 = partial begin, 2 = partial continue, 3 = partial end

        // returns packet data with old format packet length
        std::string write_old_length(std::string data) const;

        // returns packet data with new format packet length
        std::string write_new_length(std::string data) const;

        // returns first line of show functions (no tab or newline)
        virtual std::string show_title() const; // virtual to allow for overriding for special cases

        Packet(uint8_t tag);
        Packet(uint8_t tag, uint8_t version);
        Packet(const Packet & copy);

    public:
        typedef std::shared_ptr <Packet> Ptr;

        Packet();
        virtual ~Packet();
        virtual void read(std::string & data, const uint8_t part = 0) = 0;
        virtual std::string show(const uint8_t indents = 0, const uint8_t indent_size = 4) const = 0;
        virtual std::string raw() const = 0;
        std::string write(uint8_t header = 0) const; // 0 for use default; 1 for OLD; 2 for NEW

        // Accessors
        uint8_t get_tag() const;
        bool get_format() const;
        unsigned int get_version() const;
        unsigned int get_size() const;
        uint8_t get_partial() const;

        // Modifiers
        void set_tag(const uint8_t t);
        void set_format(const bool f);
        void set_version(const unsigned int v);
        void set_size(const unsigned int s);
        void set_partial(const uint8_t p);

        virtual Ptr clone() const = 0;

        Packet & operator=(const Packet & copy);
};

// For Tags 5, 6, 7, and 14
// Key is equivalent to Tag6 (but don't substitute Key for Tag6)
class Key : public Packet{
    protected:
        time_t time;
        uint8_t pka;
        std::vector <PGPMPI> mpi;

        // version 3
        uint32_t expire;

        void read_common(std::string & data);
        std::string show_common(const uint8_t indents = 0, const uint8_t indent_size = 4) const;
        std::string raw_common() const;

        Key(uint8_t tag);

    public:
        typedef std::shared_ptr <Key> Ptr;

        Key();
        Key(const Key & copy);
        Key(std::string & data);
        virtual ~Key();

        virtual void read(std::string & data, const uint8_t part = 0);
        virtual std::string show(const uint8_t indents = 0, const uint8_t indent_size = 4) const;
        virtual std::string raw() const;

        time_t get_time() const;
        uint8_t get_pka() const;
        std::vector <PGPMPI> get_mpi() const;

        void set_time(const time_t t);
        void set_pka(const uint8_t p);
        void set_mpi(const std::vector <PGPMPI> & m);

        std::string get_fingerprint() const;                      // binary
        std::string get_keyid() const;                            // binary

        virtual Packet::Ptr clone() const;

        Key & operator=(const Key & copy);
};

// For Tags 13 and 17
class ID : public Packet{
    protected:
        using Packet::Packet;

    public:
        typedef std::shared_ptr <ID> Ptr;

        ID & operator =(const ID & copy);

        virtual ~ID();
};
#endif
