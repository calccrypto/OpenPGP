/*
Sub7.h
Revocable

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

#ifndef __TAG2_SUB7__
#define __TAG2_SUB7__

#include "Packets/Tag2/Subpacket.h"

namespace OpenPGP {
    namespace Subpacket {
        namespace Tag2 {

            // 5.2.3.12. Revocable
            //
            //    (1 octet of revocability, 0 for not, 1 for revocable)
            //
            //    Signature’s revocability status. The packet body contains a Boolean
            //    flag indicating whether the signature is revocable. Signatures that
            //    are not revocable have any later revocation signatures ignored. They
            //    represent a commitment by the signer that he cannot revoke his
            //    signature for the life of his key. If this packet is not present,
            //    the signature is revocable.

            class Sub7 : public Sub {
                private:
                    bool revocable;

                    void actual_read(const std::string & data);
                    void show_contents(HumanReadable & hr) const;
                    Status actual_valid(const bool check_mpi) const;

                public:
                    typedef std::shared_ptr <Sub7> Ptr;

                    Sub7();
                    Sub7(const std::string & data);
                    std::string raw() const;

                    bool get_revocable() const;

                    void set_revocable(const bool r);

                    Sub::Ptr clone() const;
            };
        }
    }
}

#endif
