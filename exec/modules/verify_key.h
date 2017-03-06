/*
verify_key.h
OpenPGP exectuable module

Copyright (c) 2013 - 2017 Jason Lee @ calccrypto at gmail.com

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

#ifndef __COMMAND_VERIFY_KEY__
#define __COMMAND_VERIFY_KEY__

#include "../../OpenPGP.h"
#include "module.h"

namespace module {

const Module verify_key(
    // name
    "verify-key",

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
       const std::map <std::string, bool>        & flags) -> int {
        std::ifstream signer(args.at("signer-key"), std::ios::binary);
        if (!signer){
            std::cerr << "Error: Key file '" + args.at("signer-key") + "' not opened." << std::endl;
            return -1;
        }

        std::ifstream signee(args.at("signee-key"), std::ios::binary);
        if (!signee){
            std::cerr << "Error: Signing Key file '" + args.at("signee-key") + "' not opened." << std::endl;
            return -1;
        }

        PGPKey signerkey(signer), signeekey(signee);

        std::string err;
        const int verified = ::verify_key(signerkey, signeekey, err);

        if (verified == -1){
            std::cerr << err << std::endl;
        }
        else{
            std::cout << "Key in '" << args.at("signee-key") << "' was" << ((verified == 1)?"":" not") << " signed by key " << args.at("signer-key") << "." << std::endl;
        }

        return 0;
    }
);

}

#endif