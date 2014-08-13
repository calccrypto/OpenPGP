/*
Tag2Sub27.h
Key Flags

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

#ifndef __TAG2SUB27__
#define __TAG2SUB27__

#include "subpacket.h"

class Tag2Sub27 : public Tag2Subpacket{
    private:
        char flags;

    public:
        typedef std::shared_ptr <Tag2Sub27> Ptr;

        Tag2Sub27();
        Tag2Sub27(std::string & data);
        void read(std::string & data);
        std::string show(const uint8_t indents = 0, const uint8_t indent_size = 4) const;
        std::string raw() const;

        char get_flags() const;

        void set_flags(const char f);

        Tag2Subpacket::Ptr clone() const;
};
#endif
