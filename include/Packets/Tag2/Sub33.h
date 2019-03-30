/*
Sub33.h
Issuer Fingerprint

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

#ifdef GPG_COMPATIBLE

#ifndef __TAG2_SUB33__
#define __TAG2_SUB33__

#include "Packets/Tag2/Subpacket.h"

namespace OpenPGP {
    namespace Subpacket {
        namespace Tag2 {

            // This is not official (yet)
            // http://gnupg-devel.gnupg.narkive.com/Z0EFUBU7/issuer-fingerprint-was-vanity-keys
            //
            // 5.2.3.27. IssuerFingerprint
            //
            //    (N-octet Key Fingerprint)
            //
            //     The OpenPGP Fingerprint of the key issuing the signature. For
            //     current versions of OpenPGP N has the value 20. Future versions of
            //     OpenPGP may specify a different scheme for the fingerprint and thus
            //     another value for N. Implementations should thus be prepared for
            //     other fingerprint lengths but honor this Subpacket only if N is 20.

            class Sub33 : public Sub {
                private:
                    uint8_t version;
                    std::string issuer_fingerprint;

                    void actual_read(const std::string & data);
                    void show_contents(HumanReadable & hr) const;
                    Status actual_valid(const bool check_mpi) const;

                public:
                    typedef std::shared_ptr <Sub33> Ptr;

                    Sub33();
                    Sub33(const std::string & data);
                    std::string raw() const;

                    uint8_t get_version() const;
                    std::string get_issuer_fingerprint() const;

                    void set_version(const uint8_t ver);
                    void set_issuer_fingerprint(const std::string & fingerprint);

                    Sub::Ptr clone() const;
            };
        }
    }
}

#endif

#endif
