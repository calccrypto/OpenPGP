/*
Tag14.h
Public-Subkey Packet

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

#ifndef __TAG14__
#define __TAG14__

#include "Packets/Tag6.h"

namespace OpenPGP {
    namespace Packet {

        // 5.5.1.2.  Public-Subkey Packet (Tag 14)
        //
        //    A Public-Subkey packet (tag 14) has exactly the same format as a
        //    Public-Key packet, but denotes a subkey.  One or more subkeys may be
        //    associated with a top-level key.  By convention, the top-level key
        //    provides signature services, and the subkeys provide encryption
        //    services.
        //
        //    Note: in PGP 2.6.x, tag 14 was intended to indicate a comment
        //    packet.  This tag was selected for reuse because no previous version
        //    of PGP ever emitted comment packets but they did properly ignore
        //    them.  Public-Subkey packets are ignored by PGP 2.6.x and do not
        //    cause it to fail, providing a limited degree of backward
        //    compatibility.

        class Tag14 : public Tag6 {
            public:
                typedef std::shared_ptr <Packet::Tag14> Ptr;

                Tag14();
                Tag14(const Tag14 & copy);
                Tag14(const std::string & data);
                ~Tag14();

                Tag::Ptr clone() const;
        };
    }
}

#endif
