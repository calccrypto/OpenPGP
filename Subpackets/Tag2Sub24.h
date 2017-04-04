/*
Tag2Sub24.h
Preferred Key Server

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

#ifndef __TAG2_SUB24__
#define __TAG2_SUB24__

#include "Tag2Subpacket.h"

// 5.2.3.18. Preferred Key Server
//
//    (String)
//
//    This is a URI of a key server that the key holder prefers be used for
//    updates. Note that keys with multiple User IDs can have a preferred
//    key server for each User ID. Note also that since this is a URI, the
//    key server can actually be a copy of the key retrieved by ftp, http,
//    finger, etc.

class Tag2Sub24 : public Tag2Subpacket{
    private:
        std::string pks;

    public:
        typedef std::shared_ptr <Tag2Sub24> Ptr;

        Tag2Sub24();
        Tag2Sub24(const std::string & data);
        void read(const std::string & data);
        std::string show(const std::size_t indents = 0, const std::size_t indent_size = 4) const;
        std::string raw() const;

        std::string get_pks() const;

        void set_pks(const std::string & p);

        Tag2Subpacket::Ptr clone() const;
};

#endif
