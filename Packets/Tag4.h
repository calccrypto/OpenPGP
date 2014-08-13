/*
Tag4.h
One-Pass Signature Packet

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

#ifndef __TAG4__
#define __TAG4__

#include "packet.h"

class Tag4 : public Packet{
    private:
        uint8_t type;
        uint8_t hash;
        uint8_t pka;
        std::string keyid; // 8 octets
        uint8_t nested;    // A zero value indicates that the next packet is another One-Pass Signature packet that describes another signature to be applied to the same message data.

    public:
        typedef std::shared_ptr <Tag4> Ptr;

        Tag4();
        Tag4(const Tag4 & copy);
        Tag4(std::string & data);
        void read(std::string & data, const uint8_t part = 0);
        std::string show(const uint8_t indents = 0, const uint8_t indent_size = 4) const;
        std::string raw() const;

        uint8_t get_type() const;
        uint8_t get_hash() const;
        uint8_t get_pka() const;
        std::string get_keyid() const;
        uint8_t get_nested() const;

        void set_type(const uint8_t t);
        void set_hash(const uint8_t h);
        void set_pka(const uint8_t p);
        void set_keyid(const std::string & k);
        void set_nested(const uint8_t n);
    
        Packet::Ptr clone() const;
};
#endif
