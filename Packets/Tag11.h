/*
Tag11.h
Literal Data Packet

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

#ifndef __TAG11__
#define __TAG11__

#include <fstream>

#include "packet.h"

class Tag11 : public Packet{
    private:
        uint8_t format;
        std::string filename;
        uint32_t time;
        std::string literal;    // source data; no line ending conversion

    public:
        typedef std::shared_ptr <Tag11> Ptr;

        Tag11();
        Tag11(std::string & data);
        void read(std::string & data, const uint8_t part = 0);
        std::string show(const uint8_t indents = 0, const uint8_t indent_size = 4) const;
        std::string raw() const;

        uint8_t get_format() const;
        std::string get_filename() const;
        uint32_t get_time() const;
        std::string get_literal() const;
        std::string out(const bool writefile = true); // send data to 

        void set_format(const uint8_t f);
        void set_filename(const std::string & f);
        void set_time(const uint32_t t);
        void set_literal(const std::string & l);

        Packet::Ptr clone() const;
};
#endif
