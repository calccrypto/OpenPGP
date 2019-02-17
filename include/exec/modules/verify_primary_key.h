/*
verify_primary_key.h
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

#ifndef __COMMAND_VERIFY_PRIMARY_KEY__
#define __COMMAND_VERIFY_PRIMARY_KEY__

#include "../../OpenPGP.h"
#include "module.h"

namespace module {

const Module verify_primary_key(
    // name
    "verify-primary-key",

    // positional arguments
    {
        "signer-key",
        "signee-key",
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
        std::ifstream signer(args.at("signer-key"), std::ios::binary);
        if (!signer){
            err << "Error: Key file \"" + args.at("signer-key") + "\" not opened." << std::endl;
            return -1;
        }

        std::ifstream signee(args.at("signee-key"), std::ios::binary);
        if (!signee){
            err << "Error: Signing Key file \"" + args.at("signee-key") + "\" not opened." << std::endl;
            return -1;
        }

        const OpenPGP::Key signerkey(signer), signeekey(signee);

        const int verified = OpenPGP::Verify::primary_key(signerkey, signeekey);

        if (verified == -1){
            err << "Error: Bad PKA value" << std::endl;
            return -1;
        }

        out << "Key in \"" << args.at("signee-key") << "\" (" << signeekey << ") was" << ((verified == 1)?"":" not") << " signed by key in \"" << args.at("signer-key") << "\" (" << signerkey << ")." << std::endl;
        return !verified;
    }
);

}

#endif
