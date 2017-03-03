/*
Tag17.h
User Attribute Packet

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

#ifndef __TAG17__
#define __TAG17__

#include "../Subpackets/Tag17Subpackets.h"
#include "ID.h"

class Tag17 : public ID{
    public:
        typedef std::vector <Tag17Subpacket::Ptr> Attributes_T;

    private:
        uint64_t length;
        uint8_t type;

        // only defined subpacket is 1
        Attributes_T attributes;

        void read_subpacket(const std::string & data, std::string::size_type & pos, std::string::size_type & length);
        std::string write_subpacket(uint8_t s_type, std::string data) const;

    public:
        typedef std::shared_ptr <Tag17> Ptr;

        Tag17();
        Tag17(const std::string & data);
        ~Tag17();
        void read(const std::string & data);
        std::string show(const uint8_t indents = 0, const uint8_t indent_size = 4) const;
        std::string raw() const;

        Attributes_T get_attributes() const;
        Attributes_T get_attributes_clone() const;
        void set_attributes(const Attributes_T & a);

        Packet::Ptr clone() const;
};

#endif
