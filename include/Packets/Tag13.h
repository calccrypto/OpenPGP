/*
Tag13.h
User ID Packet

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

#ifndef __TAG13__
#define __TAG13__

#include "Packets/User.h"

namespace OpenPGP {
    namespace Packet {

        // 5.11. User ID Packet (Tag 13)
        //
        //    A User ID packet consists of UTF-8 text that is intended to represent
        //    the name and email address of the key holder. By convention, it
        //    includes an RFC 2822 [RFC2822] mail name-addr, but there are no
        //    restrictions on its content. The packet length in the header
        //    specifies the length of the User ID.

        class Tag13 : public User {
            private:
                std::string contents;

                void actual_read(const std::string & data, std::string::size_type & pos, const std::string::size_type & length);
                void show_contents(HumanReadable & hr) const;
                std::string actual_raw() const;
                Status actual_valid(const bool check_mpi) const;

            public:
                typedef std::shared_ptr <Packet::Tag13> Ptr;

                Tag13();
                Tag13(const std::string & data);

                std::string get_contents() const;

                void set_contents(const std::string & c);
                void set_info(const std::string & name = "", const std::string & comment = "", const std::string & email = "");

                Tag::Ptr clone() const;
        };
    }
}

#endif
