/*
Sub6.h
Regular Expression

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

#ifndef __TAG2_SUB6__
#define __TAG2_SUB6__

#include "Packets/Tag2/Subpacket.h"

namespace OpenPGP {
    namespace Subpacket {
        namespace Tag2 {

            // 5.2.3.14. Regular Expression
            //
            //    (null-terminated regular expression)
            //
            //    Used in conjunction with trust Signature packets (of level > 0) to
            //    limit the scope of trust that is extended. Only signatures by the
            //    target key on User IDs that match the regular expression in the body
            //    of this packet have trust extended by the trust Signature Subpacket.
            //    The regular expression uses the same syntax as the Henry Spencer’s
            //    "almost public domain" regular expression [REGEX] package. A
            //    description of the syntax is found in Section 8 below.

            class Sub6 : public Sub {
                private:
                    std::string regex;

                    void actual_read(const std::string & data);
                    void show_contents(HumanReadable & hr) const;
                    Status actual_valid(const bool check_mpi) const;

                public:
                    typedef std::shared_ptr <Sub6> Ptr;

                    Sub6();
                    Sub6(const std::string & data);
                    std::string raw() const;

                    std::string get_regex() const;

                    void set_regex(const std::string & r);

                    Sub::Ptr clone() const;
            };
        }
    }
}

#endif
