/*
sign_detach.h
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

#ifndef __COMMAND_SIGN_DETACH__
#define __COMMAND_SIGN_DETACH__

#include "../../OpenPGP.h"
#include "module.h"

namespace module {

const Module sign_detach(
    // name
    "sign-detach",

    // positional arguments
    {
        "private-key",
        "passphrase",
        "file",
    },

    // optional arugments
    {
        std::make_pair("o", std::make_pair("output file",                                      "")),
        std::make_pair("a", std::make_pair("armored",                                         "t")),
        std::make_pair("c", std::make_pair("certification level (0x10 - 0x13 without '0x')", "13")),
    },

    // function to run
    [](std::map <std::string, std::string> & args) -> int {
        std::ifstream k(args.at("private-key"), std::ios::binary);
        if (!k){
            std::cerr << "IOError: File '" + args.at("private-key") + "' not opened." << std::endl;
            return -1;
        }

        std::ifstream f(args.at("file"), std::ios::binary);
        if (!f){
            std::cerr << "IOError: file '" + args.at("file") + "' could not be opened." << std::endl;
            return -1;
        }

        args["-a"] = lower(args.at("a"));
        args["-h"] = upper(args.at("h"));

        if (Hash_Numbers.find(args.at("h")) == Hash_Numbers.end()){
            std::cerr << "Error: Bad Hash Algorithm Number" << std::endl;
            return -1;
        }

        PGPSecretKey pri(k);

        output(::sign_detach(pri, args.at("passphrase"), f, Hash_Numbers.at(args.at("h"))).write((args.at("a") == "f")?1:(args.at("a") == "t")?2:0), args.at("o"));

        return 0;
    }
);

}

#endif