/*
gemerate_key_pair.h
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

#ifndef __COMMAND_GENERATE_KEY_PAIR__
#define __COMMAND_GENERATE_KEY_PAIR__

#include "../../OpenPGP.h"
#include "module.h"

namespace module {

const Module generate_key_pair(
    // name
    "generatekeypair",

    // positional arguments
    {

    },

    // optional arugments
    {
        std::make_pair("o",   std::make_pair("prefix of output file",       "")),
        std::make_pair("a",   std::make_pair("armored",                    "t")),
        std::make_pair("pks", std::make_pair("public key size in bits", "2048")),
        std::make_pair("sks", std::make_pair("subkey size in bits",     "2048")),
        std::make_pair("pw",  std::make_pair("passphase",                   "")),
        std::make_pair("u",   std::make_pair("username",                    "")),
        std::make_pair("c",   std::make_pair("comment",                     "")),
        std::make_pair("e",   std::make_pair("email",                       "")),
    },

    // function to run
    [](std::map <std::string, std::string> & args) -> int {
        PGPPublicKey pub;
        PGPSecretKey pri;

        ::generate_keys(pub, pri, args.at("pw"), args.at("u"), args.at("c"), args.at("e"), mpitoulong(dectompi(args.at("pks"))), mpitoulong(dectompi(args.at("sks"))));

        output(pub.write((args.at("a") == "f")?1:(args.at("a") == "t")?2:0), args.at("o") + ".public");
        output(pri.write((args.at("a") == "f")?1:(args.at("a") == "t")?2:0), args.at("o") + ".private");

        return 0;
    }
);

}

#endif