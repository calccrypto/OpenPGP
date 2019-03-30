/*
Sub4.h
Exportable Certification

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

#ifndef __TAG2_SUB4__
#define __TAG2_SUB4__

#include "Packets/Tag2/Subpacket.h"

namespace OpenPGP {
    namespace Subpacket {
        namespace Tag2 {

            // 5.2.3.11. Exportable Certification
            //
            //    (1 octet of exportability, 0 for not, 1 for exportable)
            //
            //    This Subpacket denotes whether a certification signature is
            //    "exportable", to be used by other users than the signature’s issuer.
            //    The packet body contains a Boolean flag indicating whether the
            //    signature is exportable. If this packet is not present, the
            //    certification is exportable; it is equivalent to a flag containing a
            //    1.
            //
            //    Non-exportable, or "local", certifications are signatures made by a
            //    user to mark a key as valid within that user’s implementation only.
            //    Thus, when an implementation prepares a user’s copy of a key for
            //    transport to another user (this is the process of "exporting" the
            //    key), any local certification signatures are deleted from the key.
            //
            //    The receiver of a transported key "imports" it, and likewise trims
            //    any local certifications. In normal operation, there won’t be any,
            //    assuming the import is performed on an exported key. However, there
            //    are instances where this can reasonably happen. For example, if an
            //    implementation allows keys to be imported from a key database in
            //    addition to an exported key, then this situation can arise.
            //
            //    Some implementations do not represent the interest of a single user
            //    (for example, a key server). Such implementations always trim local
            //    certifications from any key they handle.

            class Sub4 : public Sub {
                private:
                    bool exportable;

                    void actual_read(const std::string & data);
                    void show_contents(HumanReadable & hr) const;
                    Status actual_valid(const bool check_mpi) const;

                public:
                    typedef std::shared_ptr <Sub4> Ptr;

                    Sub4();
                    Sub4(const std::string & data);
                    std::string raw() const;

                    bool get_exportable() const;

                    void set_exportable(const bool e);

                    Sub::Ptr clone() const;
            };
        }
    }
}

#endif
