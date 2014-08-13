/*
Tag5.h
Secret-Key Packet

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

#ifndef __TAG5__
#define __TAG5__

#include "Tag6.h"
#include "s2k.h"

class Tag5 : public Tag6{
    protected:
        uint8_t s2k_con;
        uint8_t sym;
        S2K::Ptr s2k;
        std::string IV;
        std::string secret;

        void read_s2k(std::string & data);
        std::string show_private(const uint8_t indents = 0, const uint8_t indent_size = 4) const;

        Tag5(uint8_t tag);

    public:
        typedef std::shared_ptr <Tag5> Ptr;

        Tag5();
        Tag5(const Tag5 & copy);
        Tag5(std::string & data);
        virtual ~Tag5();
        void read(std::string & data, const uint8_t part = 0);
        std::string show(const uint8_t indents = 0, const uint8_t indent_size = 4) const;
        std::string raw() const;

        uint8_t get_s2k_con() const;
        uint8_t get_sym() const;
        S2K::Ptr get_s2k() const;
        S2K::Ptr get_s2k_clone() const;
        std::string get_IV() const;
        std::string get_secret() const;

        Tag6 get_public_obj() const;         // extract public key from private key
        Tag6::Ptr get_public_ptr() const;    // extract public key from private key into a pointer

        void set_s2k_con(const uint8_t c);
        void set_sym(const uint8_t s);
        void set_s2k(const S2K::Ptr & s);
        void set_IV(const std::string & iv);
        void set_secret(const std::string & s);

        Packet::Ptr clone() const;
        Tag5 & operator =(const Tag5 & copy);
};
#endif
