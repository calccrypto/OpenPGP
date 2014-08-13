/*
Tag2Sub32.h
Signature Target

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

#ifndef __TAG2SUB31__
#define __TAG2SUB31__

#include "subpacket.h"

class Tag2Sub31 : public Tag2Subpacket{
    private:
        uint8_t pka;
        uint8_t ha;
        std::string hash;

    public:
        typedef std::shared_ptr <Tag2Sub31> Ptr;

        Tag2Sub31();
        Tag2Sub31(std::string & data);
        void read(std::string & data);
        std::string show(const uint8_t indents = 0, const uint8_t indent_size = 4) const;
        std::string raw() const;

        uint8_t get_pka() const;
        uint8_t get_ha() const;
        std::string get_hash() const;

        void set_pka(const uint8_t p);
        void set_ha(const uint8_t h);
        void set_hash(const std::string & h);

        Tag2Subpacket::Ptr clone() const;
};
#endif
