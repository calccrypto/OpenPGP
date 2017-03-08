/*
sign_standalone_signature.h
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

#ifndef __COMMAND_SIGN_STANDALONE_SIGNATURE__
#define __COMMAND_SIGN_STANDALONE_SIGNATURE__

#include "../../OpenPGP.h"
#include "module.h"

namespace module {

const Module sign_standalone_signature(
    // name
    "sign-standalone-signature",

    // positional arguments
    {
        "private-key",
        "passphrase",
    },

    // optional arguments
    {
        std::make_pair("-o", std::make_pair("output file",               "")),
        std::make_pair("-c", std::make_pair("compression algorithm", "ZLIB")),
        std::make_pair("-h", std::make_pair("hash_algorithm",        "SHA1")),
        std::make_pair("-u", std::make_pair("User Identifier",           "")),
    },

    // optional flags
    {
        std::make_pair("-a", "armored"),
    },

    // function to run
    [](const std::map <std::string, std::string> & args,
       const std::map <std::string, bool>        & flags) -> int {
        std::ifstream key(args.at("private-key"), std::ios::binary);
        if (!key){
            std::cerr << "IOError: File '" + args.at("private-key") + "' not opened." << std::endl;
            return -1;
        }

        if (Compression::NUMBER.find(args.at("-c")) == Compression::NUMBER.end()){
            std::cerr << "Error: Bad Compression Algorithm: " << args.at("-c") << std::endl;
            return -1;
        }

        if (Hash::NUMBER.find(args.at("-h")) == Hash::NUMBER.end()){
            std::cerr << "Error: Bad Hash Algorithm: " << args.at("-n") << std::endl;
            return -1;
        }

        const SignArgs signargs(PGPSecretKey(key),
                                args.at("passphrase"),
                                args.at("-u"),
                                4,
                                Hash::NUMBER.at(args.at("-h")));

        // for now, just sign own signature packet
        std::string error;
        PGPDetachedSignature signature = ::sign_standalone_signature(signargs, std::static_pointer_cast <Tag2> (signargs.pri.get_packets()[2]), Compression::NUMBER.at(args.at("-c")), error);

        if (signature.meaningful()){
            output(signature.write(flags.at("-a")?PGP::Armored::YES:PGP::Armored::NO), args.at("-o"));
        }
        else{
            std::cerr << error << std::endl;
        }

        return 0;
    }
);

}

#endif