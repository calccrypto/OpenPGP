/*
Tag2Sub21.h
Preferred Hash Algorithms

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

#ifndef __TAG2SUB21__
#define __TAG2SUB21__

#include "subpacket.h"

class Tag2Sub21 : public Tag2Subpacket{
    private:
        std::string pha;

    public:
        typedef std::shared_ptr <Tag2Sub21> Ptr;

        Tag2Sub21();
        Tag2Sub21(std::string & data);
        void read(std::string & data);
        std::string show(const uint8_t indents = 0, const uint8_t indent_size = 4) const;
        std::string raw() const;

        std::string get_pha() const;  // returns string of preferred hash algorithms (ex: "\x01\x02\x03")

        void set_pha(const std::string & p);

        Tag2Subpacket::Ptr clone() const;
};
#endif
