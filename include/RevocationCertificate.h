/*
RevocationCertificate.h
Revocation Certificate data structure

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

#ifndef __OPENPGP_REVOCATION_CERTIFICATE__
#define __OPENPGP_REVOCATION_CERTIFICATE__

#include "PGP.h"

namespace OpenPGP {
    class RevocationCertificate : public PGP {
        public:
            typedef std::shared_ptr <RevocationCertificate> Ptr;

            RevocationCertificate();
            RevocationCertificate(const PGP & copy);
            RevocationCertificate(const RevocationCertificate & copy);
            RevocationCertificate(const std::string & data);
            RevocationCertificate(std::istream & stream);
            ~RevocationCertificate();

            uint8_t get_revoke_type() const;

            // whether or not PGP data matches Revocation Certificate format without constructing a new object
            static bool meaningful(const PGP & pgp);

            // whether or not *this data matches Revocation Certificate format
            bool meaningful() const;

            PGP::Ptr clone() const;
    };

}

#endif
