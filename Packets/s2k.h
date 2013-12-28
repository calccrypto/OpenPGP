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

#include <iostream>
#include <sstream>

#include "../common/includes.h"
#include "../consts.h"
#include "../usehash.h"

#ifndef __S2K__
#define __S2K__

#define EXPBIAS 6
uint32_t coded_count(unsigned int c);

class S2K{
    protected:
        uint8_t type;
        uint8_t hash;
        std::string show_octect0();
        std::string show_octect1();

    public:
        virtual ~S2K();
        virtual void read(std::string & data) = 0;
        virtual std::string show() = 0;
        virtual std::string raw() = 0;
        std::string write();
        virtual std::string run(std::string pass, unsigned int sym_len) = 0;

        virtual S2K * clone() = 0;

        uint8_t get_type();
        uint8_t get_hash();

        void set_type(const uint8_t t);
        void set_hash(const uint8_t h);
};

class S2K0: public S2K{
    public:
        S2K0();
        virtual ~S2K0();
        virtual void read(std::string & data);
        virtual std::string show();
        virtual std::string raw();
        virtual std::string run(std::string pass, unsigned int sym_len);
        S2K0 copy();
        S2K0 * clone();
};

class S2K1 : public S2K0{
    protected:
        std::string salt;   // 8 octets

    public:
        S2K1();
        virtual ~S2K1();
        virtual void read(std::string & data);
        virtual std::string show();
        virtual std::string raw();
        virtual std::string run(std::string pass, unsigned int sym_len);

        S2K1 copy();
        S2K1 * clone();

        std::string get_salt();

        void set_salt(const std::string & s);
};

class S2K3 : public S2K1{
    private:
        uint8_t count;

    public:
        S2K3();
        ~S2K3();
        void read(std::string & data);
        std::string show();
        std::string raw();
        std::string run(std::string pass, unsigned int sym_len);

        S2K3 copy();
        S2K3 * clone();

        uint8_t get_count();

        void set_count(const uint8_t c);
};
#endif
