/*
Sub24.h
Preferred Key Server

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

#ifndef __TAG2_SUB24__
#define __TAG2_SUB24__

#include "Packets/Tag2/Subpacket.h"

namespace OpenPGP {
    namespace Subpacket {
        namespace Tag2 {

            // 5.2.3.18. Preferred Key Server
            //
            //    (String)
            //
            //    This is a URI of a key server that the key holder prefers be used for
            //    updates. Note that keys with multiple User IDs can have a preferred
            //    key server for each User ID. Note also that since this is a URI, the
            //    key server can actually be a copy of the key retrieved by ftp, http,
            //    finger, etc.

            class Sub24 : public Sub {
                private:
                    std::string pks;

                    void actual_read(const std::string & data);
                    void show_contents(HumanReadable & hr) const;
                    Status actual_valid(const bool check_mpi) const;

                public:
                    typedef std::shared_ptr <Sub24> Ptr;

                    Sub24();
                    Sub24(const std::string & data);
                    std::string raw() const;

                    std::string get_pks() const;

                    void set_pks(const std::string & p);

                    Sub::Ptr clone() const;
            };
        }
    }
}

#endif
