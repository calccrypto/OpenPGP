/*
Tag6.h
Public-Key Packet

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

#ifndef __TAG6__
#define __TAG6__

#include "../Hashes/Hashes.h"
#include "packet.h"

class Tag6 : public Key{
    protected:
        time_t time;
        uint8_t pka;
        std::vector <PGPMPI> mpi;

        // version 3
        uint32_t expire;

        void read_tag6(std::string & data);
        std::string show_tag6(const uint8_t indents = 0, const uint8_t indent_size = 4) const;
        std::string raw_tag6() const;

        Tag6(uint8_t tag);

    public:
        typedef std::shared_ptr<Tag6> Ptr;

        Tag6();
        Tag6(std::string & data);
        virtual ~Tag6();

        virtual void read(std::string & data);
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

        Packet::Ptr clone() const;

        Tag6(const Tag6 & copy);
        Tag6& operator=(const Tag6 & copy);

};
#endif
