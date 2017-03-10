/*
verify_message.h
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

#ifndef __COMMAND_VERIFY_MESSAGE__
#define __COMMAND_VERIFY_MESSAGE__

#include "../../OpenPGP.h"
#include "module.h"

namespace module {

const Module verify_message(
    // name
    "verify-message",

    // positional arguments
    {
        "key",
        "message",
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
            std::cerr << "Error: Key file '" + args.at("key") + "' not opened." << std::endl;
            return -1;
        }

        std::ifstream msg(args.at("message"), std::ios::binary);
        if (!msg){
            std::cerr << "Error: Message file '" + args.at("message") + "' not opened." << std::endl;
            return -1;
        }

        PGPKey signer(key);
        PGPMessage message(msg);

        std::string error;
        const int verified = ::verify_message(signer, message, error);

        if (verified == -1){
            std::cerr << error << std::endl;
        }
        else{
            std::cout << "The data in '" << args.at("message") << "' was" << ((verified == 1)?"": " not") << " signed by " << signer << std::endl;
        }

        return 0;
    }
);

}

#endif