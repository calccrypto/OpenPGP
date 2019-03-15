/*
Tag7.h
Secret-Subkey Packet

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

#ifndef __TAG7__
#define __TAG7__

#include "Packets/Tag5.h"
#include "Packets/Tag14.h"

namespace OpenPGP {
    namespace Packet {

        // 5.5.1.4.  Secret-Subkey Packet (Tag 7)
        //
        //    A Secret-Subkey packet (tag 7) is the subkey analog of the Secret
        //    Key packet and has exactly the same format.

        class Tag7 : public Tag5 {
            public:
                typedef std::shared_ptr <Packet::Tag7> Ptr;

                Tag7();
                Tag7(const std::string & data);
                ~Tag7();

                Tag14 get_public_obj() const;       // extract public subkey from private key
                Tag14::Ptr get_public_ptr() const;  // extract public subkey from private key into a pointer

                Tag::Ptr clone() const;
        };
    }
}

#endif
