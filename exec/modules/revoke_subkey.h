/*
revoke_subkey.h
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

#ifndef __COMMAND_REVOKE_SUBKEY
#define __COMMAND_REVOKE_SUBKEY

#include "../../OpenPGP.h"
#include "module.h"

namespace module {

const Module revoke_subkey(
    // name
    "revoke-subkey",

    // positional arguments
    {
        "private-key",
        "passphrase",
    },

    // optional arguments
    {
        std::make_pair("-o", std::make_pair("output file",   "")),
        std::make_pair("-c", std::make_pair("code (0-3)",   "0")),
        std::make_pair("-r", std::make_pair("reason",        "")),
    },

    // optional flags
    {
        std::make_pair("-a", "armored"),
    },

    // function to run
    [](const std::map <std::string, std::string> & args,
       const std::map <std::string, bool>        & flags) -> int {
        std::ifstream file(args.at("private-key"), std::ios::binary);
        if (!file){
            std::cerr << "IOError: File '" + args.at("private-key") + "' not opened." << std::endl;
            return -1;
        }

        PGPSecretKey pri(file);

        // find private subkey
        bool found = false;
        for(Packet::Ptr const & p : pri.get_packets()){
            if (p -> get_tag() == Packet::SECRET_SUBKEY){
                found = true;
                break;
            }
        }

        if (!found){
            std::cerr << "Error: No Private Subkey Packet (Tag 5) found." << std::endl;
            return -1;
        }

        output(::revoke_subkey(pri,
                               args.at("passphrase"),
                               args.at("-c")[0] - '0',
                               args.at("-r")).write(flags.at("-a")?PGP::Armored::YES:PGP::Armored::NO), args.at("-o"));

        return 0;
    }
);

}

#endif