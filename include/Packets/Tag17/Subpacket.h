/*
Subpacket.h
Base class for OpenPGP Tag 17 Subpackets to inherit from

Copyright (c) 2013 - 2019 Jason Lee @ calccrypto at gmail.com

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

#include "Packets/Subpacket.h"

namespace OpenPGP {
    namespace Subpacket {
        namespace Tag17 {
            constexpr uint8_t IMAGE_ATTRIBUTE = 1;

            const std::map <uint8_t, std::string> NAME = {
                std::make_pair(IMAGE_ATTRIBUTE, "Image Attribute"),
            };

            class Sub: public Subpacket::Sub {
                protected:
                    std::string show_type() const;

                    Sub(uint8_t type = 0, unsigned int size = 0, bool crit = false);

                public:
                    typedef std::shared_ptr <Sub> Ptr;

                    virtual ~Sub();

                    virtual Ptr clone() const = 0;
            };
        }
    }
}

#endif
