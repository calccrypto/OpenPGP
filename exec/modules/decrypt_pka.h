/*
decrypt_pka.h
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

#ifndef __COMMAND_DECRYPT_PKA__
#define __COMMAND_DECRYPT_PKA__

#include "../../OpenPGP.h"
#include "module.h"

namespace module {

const Module decrypt_pka(
    // name
    "decrypt-pka",

    // positional arguments
    {
        "private-key",
        "passphrase",
        "file",
    },

    // optional arugments
    {
        std::make_pair("a", std::make_pair("armored",            "t")),
        std::make_pair("d", std::make_pair("delete original?",   "f")),
        std::make_pair("v", std::make_pair("signing public key",  "")),
        std::make_pair("w", std::make_pair("write to file?",     "t")),
    },

    // function to run
    [](std::map <std::string, std::string> & args) -> int {
        std::ifstream k(args.at("private-key"), std::ios::binary);
        if (!k){
            std::cerr << "Error: File '" + args.at("private-key") + "' not opened." << std::endl;
            return -1;
        }

        std::ifstream m(args.at("file"), std::ios::binary);
        if (!m){
            std::cerr << "Error: File '" + args.at("file") + "' not opened." << std::endl;
            return -1;
        }

        args["-a"] = lower(args.at("a"));
        args["-d"] = lower(args.at("d"));
        args["-w"] = lower(args.at("w"));

        PGPPublicKey::Ptr signer = nullptr;
        if (args.at("v").size()){
            std::ifstream v(args.at("v"), std::ios::binary);
            if (!v){
                std::cerr << "Error: File '" + args.at("v") + "' not opened." << std::endl;
                return -1;
            }

            signer = std::make_shared <PGPPublicKey> (v);
        }

        PGPSecretKey pri(k);
        PGPMessage msg(m);

        output(::decrypt_pka(pri, msg, args.at("passphrase"), (args.at("w") == "t"), signer), "");

        if (args.at("d") == "t"){
            remove(args.at("file").c_str());
        }

        return 0;
    }
);

}

#endif