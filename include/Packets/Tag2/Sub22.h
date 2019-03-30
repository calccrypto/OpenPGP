/*
Sub22.h
Preferred Compression Algorithms

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

#ifndef __TAG2_SUB22__
#define __TAG2_SUB22__

#include "Compress/Compress.h"
#include "Packets/Tag2/Subpacket.h"

namespace OpenPGP {
    namespace Subpacket {
        namespace Tag2 {

            // 5.2.3.9. Preferred Compression Algorithms
            //
            //    (array of one-octet values)
            //
            //    Compression algorithm numbers that indicate which algorithms the key
            //    holder prefers to use. Like the preferred symmetric algorithms, the
            //    list is ordered. Algorithm numbers are in Section 9. If this
            //    Subpacket is not included, ZIP is preferred. A zero denotes that
            //    uncompressed data is preferred; the key holder’s software might have
            //    no compression software in that implementation. This is only found
            //    on a self-signature.

            class Sub22 : public Sub {
                private:
                    std::string pca;

                    void actual_read(const std::string & data);
                    void show_contents(HumanReadable & hr) const;
                    Status actual_valid(const bool check_mpi) const;

                public:
                    typedef std::shared_ptr <Sub22> Ptr;

                    Sub22();
                    Sub22(const std::string & data);
                    std::string raw() const;

                    std::string get_pca() const;

                    void set_pca(const std::string & c);

                    Sub::Ptr clone() const;
            };
        }
    }
}

#endif
