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
#include <vector>

#include "../common/includes.h"
#include "../consts.h"
#include "../mpi.h"
#include "../pgptime.h"

class Packet{
    protected:
        uint8_t tag;
        uint8_t version;
        bool format;     // OLD or NEW; only used when "show"ing. "write" will write whatever it set; default is NEW
        unsigned int size;  // This value is only correct when the packet was generated with the read() function

        // returns packet data with old format packet length
        std::string write_old_length(std::string data) const;

        // returns packet data with new format packet length
        std::string write_new_length(std::string data) const;

        Packet(uint8_t tag);
        Packet(uint8_t tag, uint8_t version);
        Packet(const Packet & copy);

        Packet & operator =(const Packet & copy);

    public:
        typedef std::shared_ptr<Packet> Ptr;

        Packet();
        virtual ~Packet();
        virtual void read(std::string & data) = 0;
        virtual std::string show() const = 0;
        virtual std::string raw() const = 0;
        std::string write(uint8_t header = 0) const; // 0 for use default; 1 for OLD; 2 for NEW

        // Accessors
        uint8_t get_tag() const;
        bool get_format() const;
        unsigned int get_version() const;
        unsigned int get_size() const;

        // Modifiers
        void set_tag(const uint8_t t);
        void set_format(const bool f);
        void set_version(const unsigned int v);
        void set_size(const unsigned int s);

        virtual Ptr clone() const = 0;
};

// For Tags 5, 6, 7, and 14
class Key : public Packet{
    protected:
        using Packet::Packet;

        Key & operator =(const Key & copy);

    public:
        typedef std::shared_ptr<Key> Ptr;

        virtual ~Key();
};

// For Tags 13 and 17
class ID : public Packet{
    protected:
        using Packet::Packet;

        ID & operator =(const ID & copy);

    public:
        typedef std::shared_ptr<ID> Ptr;

        virtual ~ID();
};
#endif
