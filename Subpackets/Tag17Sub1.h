/*
Tag17Sub1.h
Image Attribute

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

#ifndef __TAG17SUB1__
#define __TAG17SUB1__

#include "subpacket.h"

class Tag17Sub1 : public Tag17Subpacket{
    private:
        uint8_t version;
        uint8_t encoding;
        std::string image;

        static unsigned int count;  // count of all images found; incremented by creating new instances of Tag17Sub1
        unsigned int current;       // which image this instance is
        
    public:
        typedef std::shared_ptr <Tag17Sub1> Ptr;

        Tag17Sub1();
        Tag17Sub1(std::string & data);
        void read(std::string & data);
        std::string show(const uint8_t indents = 0, const uint8_t indent_size = 4) const;
        std::string raw() const;

        std::string get_image() const;

        void set_image(const std::string & i);

        Tag17Subpacket::Ptr clone() const;
};
#endif
