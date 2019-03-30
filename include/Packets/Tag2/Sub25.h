/*
Sub25.h
Primary User ID

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

#ifndef __TAG2_SUB25__
#define __TAG2_SUB25__

#include "Packets/Tag2/Subpacket.h"

namespace OpenPGP {
    namespace Subpacket {
        namespace Tag2 {

            // 5.2.3.19. Primary User ID
            //
            //    (1 octet, Boolean)
            //
            //    This is a flag in a User ID’s self-signature that states whether this
            //    User ID is the main User ID for this key. It is reasonable for an
            //    implementation to resolve ambiguities in preferences, etc. by
            //    referring to the primary User ID. If this flag is absent, its value
            //    is zero. If more than one User ID in a key is marked as primary, the
            //    implementation may resolve the ambiguity in any way it sees fit, but
            //    it is RECOMMENDED that priority be given to the User ID with the most
            //    recent self-signature.
            //
            //    When appearing on a self-signature on a User ID packet, this
            //    Subpacket applies only to User ID packets. When appearing on a
            //    self-signature on a User Attribute packet, this Subpacket applies
            //    only to User Attribute packets. That is to say, there are two
            //    different and independent "primaries" -- one for User IDs, and one
            //    for User Attributes.

            class Sub25 : public Sub {
                private:
                    bool primary;

                    void actual_read(const std::string & data);
                    void show_contents(HumanReadable & hr) const;
                    Status actual_valid(const bool check_mpi) const;

                public:
                    typedef std::shared_ptr <Sub25> Ptr;

                    Sub25();
                    Sub25(const std::string & data);
                    std::string raw() const;

                    bool get_primary() const;

                    void set_primary(const bool p);

                    Sub::Ptr clone() const;
            };
        }
    }
}
#endif
