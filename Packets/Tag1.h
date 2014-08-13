/*
Tag1.h
Public-Key Encrypted Session Key Packet

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

#ifndef __TAG1__
#define __TAG1__

#include "packet.h"
class Tag1 : public Packet{
    private:
        std::string keyid;                // 8 octets
        uint8_t pka;
        std::vector <PGPMPI> mpi;         // algorithm specific fields

    public:
        typedef std::shared_ptr <Tag1> Ptr;

        Tag1();
        Tag1(std::string & data);
        void read(std::string & data, const uint8_t part = 0);
        std::string show(const uint8_t indents = 0, const uint8_t indent_size = 4) const;
        std::string raw() const;

        std::string get_keyid() const;
        uint8_t get_pka() const;
        std::vector <PGPMPI> get_mpi() const;

        void set_keyid(const std::string & k);
        void set_pka(const uint8_t p);
        void set_mpi(const std::vector <PGPMPI> & m);

        Packet::Ptr clone() const;
};
#endif
