/*
Sub28.h
Signer's User ID

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

#ifndef __TAG2_SUB28__
#define __TAG2_SUB28__

#include "Packets/Tag2/Subpacket.h"

namespace OpenPGP {
    namespace Subpacket {
        namespace Tag2 {

            // 5.2.3.22.  Signer's User ID
            //
            //    (String)
            //
            //    This Subpacket allows a keyholder to state which User ID is
            //    responsible for the signing.  Many keyholders use a single key for
            //    different purposes, such as business communications as well as
            //    personal communications.  This Subpacket allows such a keyholder to
            //    state which of their roles is making a signature.
            //
            //    This Subpacket is not appropriate to use to refer to a User Attribute
            //    packet.

            class Sub28 : public Sub {
                private:
                    std::string signer;

                    void actual_read(const std::string & data);
                    void show_contents(HumanReadable & hr) const;
                    Status actual_valid(const bool check_mpi) const;

                public:
                    typedef std::shared_ptr <Sub28> Ptr;

                    Sub28();
                    Sub28(const std::string & data);
                    std::string raw() const;

                    std::string get_signer() const;

                    void set_signer(const std::string & s);

                    Sub::Ptr clone() const;
            };
        }
    }
}

#endif
