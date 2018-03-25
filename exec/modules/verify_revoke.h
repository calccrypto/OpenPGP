/*
verify_revoke.h
OpenPGP exectuable module

Copyright (c) 2013 - 2018 Jason Lee @ calccrypto at gmail.com

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

#ifndef __COMMAND_VERIFY_REVOKE__
#define __COMMAND_VERIFY_REVOKE__

#include "../../OpenPGP.h"
#include "module.h"

namespace module {

const Module verify_revoke(
    // name
    "verify-revoke",

    // positional arguments
    {
        "key",
        "revocation-certificate",
    },

    // optional arguments
    {

    },

    // optional flags
    {

    },

    // function to run
    [](const std::map <std::string, std::string> & args,
       const std::map <std::string, bool>        & flags,
       std::ostream                              & out,
       std::ostream                              & err) -> int {
        std::ifstream key(args.at("key"), std::ios::binary);
        if (!key){
            err << "Error: Public key file \"" + args.at("key") + "\" not opened." << std::endl;
            return -1;
        }

        std::ifstream cert(args.at("revocation-certificate"), std::ios::binary);
        if (!cert){
            err << "Error: Revocation certificate file \"" + args.at("revocation-certificate") + "\" not opened." << std::endl;
            return -1;
        }

        const OpenPGP::Key signer(key);
        const OpenPGP::RevocationCertificate rev(cert);

            const int verified = OpenPGP::Verify::revoke(signer, rev);

        if (verified == -1){
            err << "Error: Bad PKA value" << std::endl;
            return -1;
        }

        out << "The certificate in \"" << args.at("revocation-certificate") << "\" " << ((verified == 1)?std::string("revokes"):std::string("does not revoke")) << " key in \"" << args.at("key") << "\" (" << signer << ")." << std::endl;
        return !verified;
    }
);

}

#endif
