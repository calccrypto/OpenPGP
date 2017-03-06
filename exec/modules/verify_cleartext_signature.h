/*
verify_cleartext_signature.h
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

#ifndef __COMMAND_VERIFY_CLEARTEXT_SIGNATURE__
#define __COMMAND_VERIFY_CLEARTEXT_SIGNATURE__

#include "../../OpenPGP.h"
#include "module.h"

namespace module {

const Module verify_cleartext_signature(
    // name
    "verify-cleartext-signature",

    // positional arguments
    {
        "key",
        "signature",
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
        std::ifstream key(args.at("key"), std::ios::binary);
        if (!key){
            std::cerr << "Error: File '" + args.at("key") + "' not opened." << std::endl;
            return -1;
        }

        std::ifstream sig(args.at("signature"), std::ios::binary);
        if (!sig){
            std::cerr << "Error: File '" + args.at("signature") + "' not opened." << std::endl;
            return -1;
        }

        PGPKey signer(key);
        PGPCleartextSignature signature(sig);

        std::string err;
        const int verified = ::verify_cleartext_signature(signer, signature, err);

        if (verified == -1){
            std::cerr << err << std::endl;
        }
        else{
            std::cout << "This message was" << ((verified == 1)?"":" not") << " signed by this key." << std::endl;
        }

        return 0;
    }
);

}

#endif