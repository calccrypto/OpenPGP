/*
subpacket.h
Base class for OpenPGP subpackets to inherit from

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

#ifndef __SUBPACKET__
#define __SUBPACKET__

#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>

#include "../common/includes.h"
#include "../consts.h"
#include "../pgptime.h"

class Subpacket{
    protected:
        uint8_t type;
        unsigned int size; // only used for displaying. recalculated when writing

        std::string write_subpacket(const std::string & data) const;

        // returns first line of show functions (no tab or newline)
        std::string show_title() const;
        
        Subpacket(uint8_t type = 0, unsigned int size = 0);
        Subpacket(const Subpacket & copy);
        Subpacket & operator =(const Subpacket & copy);

    public:
        typedef std::shared_ptr <Subpacket> Ptr;

        virtual ~Subpacket();
        virtual void read(std::string & data) = 0;
        virtual std::string show(const uint8_t indents = 0, const uint8_t indent_size = 4) const = 0;
        virtual std::string raw() const = 0; // returns raw subpacket data, with no header
        std::string write() const;

        uint8_t get_type() const;
        unsigned int get_size() const;

        void set_type(uint8_t t);
        void set_size(unsigned int s);
};

class Tag2Subpacket: public Subpacket {
    protected:
        using Subpacket::Subpacket;

        Tag2Subpacket & operator =(const Tag2Subpacket & copy);

    public:
        typedef std::shared_ptr <Tag2Subpacket> Ptr;

        virtual ~Tag2Subpacket();
        
        virtual Ptr clone() const = 0;
};

class Tag17Subpacket: public Subpacket {
    protected:
        using Subpacket::Subpacket;

        Tag17Subpacket & operator =(const Tag17Subpacket & copy);

    public:
        typedef std::shared_ptr <Tag17Subpacket> Ptr;

        virtual ~Tag17Subpacket();
        
        virtual Ptr clone() const = 0;

};
#endif
