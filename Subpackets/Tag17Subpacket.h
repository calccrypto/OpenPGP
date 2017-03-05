/*
Tag17Subpacket.h
Base class for OpenPGP Tag 17 subpackets to inherit from

Copyright (c) 2013 - 2017 Jason Lee @ calccrypto at gmail.com

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

#ifndef __TAG17_SUBPACKET__
#define __TAG17_SUBPACKET__

#include <map>
#include <string>

#include "Subpacket.h"

class Tag17Subpacket: public Subpacket {
    public:
        class ID{
            public:
                static const uint8_t Image_Attribute;
        };

        static const std::map <uint8_t, std::string> Name;

    protected:
        using Subpacket::Subpacket;

        std::string show_title() const;

        Tag17Subpacket & operator=(const Tag17Subpacket & copy);

    public:
        typedef std::shared_ptr <Tag17Subpacket> Ptr;

        virtual ~Tag17Subpacket();

        virtual Ptr clone() const = 0;
};

#endif