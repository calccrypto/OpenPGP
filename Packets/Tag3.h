/*
Tag3.h
Symmetric-Key Encrypted Session Key Packet

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

#ifndef __TAG3__
#define __TAG3__

#include "../cfb.h"
#include "packet.h"
#include "s2k.h"

class Tag3 : public Packet{
    private:
        uint8_t sym;
        S2K::Ptr s2k;
        std::shared_ptr <std::string> esk; // encrypted session key

    public:
        typedef std::shared_ptr <Tag3> Ptr;

        Tag3();
        Tag3(const Tag3 & copy);
        Tag3(std::string & data);
        ~Tag3();
        void read(std::string & data, const uint8_t part = 0);
        std::string show(const uint8_t indents = 0, const uint8_t indent_size = 4) const;
        std::string raw() const;

        uint8_t get_sym() const;
        S2K::Ptr get_s2k() const;
        S2K::Ptr get_s2k_clone() const;
        std::shared_ptr <std::string> get_esk() const;
        std::shared_ptr <std::string> get_esk_clone() const;
        std::string get_key(const std::string & pass) const;

        void set_sym(const uint8_t s);
        void set_s2k(const S2K::Ptr & s);
        void set_esk(std::string * s);
        void set_esk(const std::string & s);
        void set_key(const std::string & pass, const std::string & sk = "");    // passing in empty sk will erase esk                

        Packet::Ptr clone() const;
        Tag3 & operator=(const Tag3 & tag3);
};
#endif
