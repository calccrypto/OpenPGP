/*
revoke.h
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

#ifndef __COMMAND_REVOKE__
#define __COMMAND_REVOKE__

#include "../../OpenPGP.h"
#include "module.h"

namespace module {

const Module revoke(
    // name
    "revoke",

    // positional arguments
    {
        "target",
        "revocation-certificate",
    },

    // optional arguments
    {
        std::make_pair("-o", std::make_pair("output file", "")),
    },

    // optional flags
    {
        std::make_pair("-a", "armored"),
    },

    // function to run
    [](const std::map <std::string, std::string> & args,
       const std::map <std::string, bool>        & flags) -> int {
        std::ifstream target(args.at("target"), std::ios::binary);
        if (!target){
            std::cerr << "IOError: File '" + args.at("target") + "' not opened." << std::endl;
            return -1;
        }

        std::ifstream cert(args.at("revocation-certificate"), std::ios::binary);
        if (!cert){
            std::cerr << "IOError: File '" + args.at("revocation-certificate") + "' not opened." << std::endl;
            return -1;
        }
        PGPSecretKey pri(target);
        PGPPublicKey rev(cert);

        output(::revoke_with_cert(pri, rev).write((!flags.at("-a"))?1:flags.at("-a")?2:0), args.at("-o"));

        return 0;
    }
);

}
#endif