/*
Sub12.h
Revocation Key

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

#ifndef __TAG2_SUB12__
#define __TAG2_SUB12__

#include "PKA/PKAs.h"
#include "Packets/Tag2/Subpacket.h"

namespace OpenPGP {
    namespace Subpacket {
        namespace Tag2 {

            // 5.2.3.15. Revocation Key
            //
            //    (1 octet of class, 1 octet of public-key algorithm ID, 20 octets of
            //    fingerprint)
            //
            //    Authorizes the specified key to issue revocation signatures for this
            //    key. Class octet must have bit 0x80 set. If the bit 0x40 is set,
            //    then this means that the revocation information is sensitive. Other
            //    bits are for future expansion to other kinds of authorizations. This
            //    is found on a self-signature.
            //
            //    If the "sensitive" flag is set, the keyholder feels this Subpacket
            //    contains private trust information that describes a real-world
            //    sensitive relationship. If this flag is set, implementations SHOULD
            //    NOT export this signature to other users except in cases where the
            //    data needs to be available: when the signature is being sent to the
            //    designated revoker, or when it is accompanied by a revocation
            //    signature from that revoker. Note that it may be appropriate to
            //    isolate this Subpacket within a separate signature so that it is not
            //    combined with other Subpackets that need to be exported.

            class Sub12 : public Sub {
                private:
                    uint8_t _class;
                    uint8_t pka;
                    std::string fingerprint; // 20 octets

                    void actual_read(const std::string & data);
                    Status actual_valid(const bool check_mpi) const;

                public:
                    typedef std::shared_ptr <Sub12> Ptr;

                    Sub12();
                    Sub12(const std::string & data);
                    void show_contents(HumanReadable & hr) const;
                    std::string raw() const;

                    uint8_t get_class() const;
                    uint8_t get_pka() const;
                    std::string get_fingerprint() const;

                    void set_class(const uint8_t c);
                    void set_pka(const uint8_t p);
                    void set_fingerprint(const std::string & f);

                    Sub::Ptr clone() const;
            };
        }
    }
}

#endif
