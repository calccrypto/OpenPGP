/*
s2k.h
String-to-Key Specifiers data structures as described in RFC 4880 sec 3.7

Copyright (c) 2013 Jason Lee

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

#ifndef __S2K__
#define __S2K__

#include <iostream>
#include <memory>
#include <sstream>

#include "../common/includes.h"
#include "../Hashes/Hashes.h"
#include "../consts.h"

#define EXPBIAS 6
uint32_t coded_count(unsigned int c);

// Base Class
class S2K{
    protected:
        uint8_t type; // octet 0
        uint8_t hash; // octet 1

        std::string show_title() const;
        
        S2K(uint8_t type);

    public:
        typedef std::shared_ptr <S2K> Ptr;

        virtual ~S2K();
        virtual void read(std::string & data, const uint8_t part = 0) = 0;
        virtual std::string show(const uint8_t indents = 0, const uint8_t indent_size = 4) const = 0;
        virtual std::string raw() const = 0;
        std::string write() const;
        virtual std::string run(const std::string & pass, unsigned int sym_key_len) const = 0;

        uint8_t get_type() const;
        uint8_t get_hash() const;

        void set_type(const uint8_t t);
        void set_hash(const uint8_t h);

        virtual Ptr clone() const = 0;
};

// Simple S2K
class S2K0: public S2K{
    protected:
        S2K0(uint8_t type);

    public:
        typedef std::shared_ptr <S2K0> Ptr;

        S2K0();
        virtual ~S2K0();
        virtual void read(std::string & data, const uint8_t part = 0);
        virtual std::string show(const uint8_t indents = 0, const uint8_t indent_size = 4) const;
        virtual std::string raw() const;
        virtual std::string run(const std::string & pass, unsigned int sym_key_len) const;

        S2K::Ptr clone() const;
};

// Salted S2K
class S2K1 : public S2K0{
    protected:
        std::string salt;   // 8 octets

        S2K1(uint8_t type);

    public:
        typedef std::shared_ptr <S2K1> Ptr;

        S2K1();
        virtual ~S2K1();
        virtual void read(std::string & data, const uint8_t part = 0);
        virtual std::string show(const uint8_t indents = 0, const uint8_t indent_size = 4) const;
        virtual std::string raw() const;
        virtual std::string run(const std::string & pass, unsigned int sym_key_len) const;

        std::string get_salt() const;

        void set_salt(const std::string & s);

        S2K::Ptr clone() const;
};

// Iterated and Salted S2K
class S2K3 : public S2K1{
    private:
        uint8_t count;

    public:
        typedef std::shared_ptr <S2K3> Ptr;

        S2K3();
        ~S2K3();
        void read(std::string & data, const uint8_t part = 0);
        std::string show(const uint8_t indents = 0, const uint8_t indent_size = 4) const;
        std::string raw() const;
        std::string run(const std::string & pass, unsigned int sym_key_len) const;

        uint8_t get_count() const;

        void set_count(const uint8_t c);

        S2K::Ptr clone() const;
};
#endif
