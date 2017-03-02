/*
verify_revoke.h
OpenPGP exectuable module

Copyright (c) 2013 - 2017 Jason Lee @ calccrypto@gmail.com

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
        "public-key",
        "revocation-certificate",
    },

    // optional arugments
    {

    },

    // function to run
    [](std::map <std::string, std::string> & args) -> int {
        std::ifstream k(args.at("public-key"), std::ios::binary);
        if (!k){
            std::cerr << "Error: Public key file '" + args.at("public-key") + "' not opened." << std::endl;
            return -1;
        }

        std::ifstream c(args.at("revocation-certificate"), std::ios::binary);
        if (!c){
            std::cerr << "Error: Revocation certificate file '" + args.at("revocation-certificate") + "' not opened." << std::endl;
            return -1;
        }

        PGPPublicKey pub(k);
        PGPPublicKey cert(c);

        std::cout << "The certificate in '" << args.at("revocation-certificate") << "' " << (::verify_revoke(pub, cert)?std::string("revokes"):std::string("does not revoke")) << " key " << pub << std::endl;

        return 0;
    }
);

}

#endif