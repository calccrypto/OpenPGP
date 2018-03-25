/*
sign_timestamp.h
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

#ifndef __COMMAND_SIGN_TIMESTAMP__
#define __COMMAND_SIGN_TIMESTAMP__

#include "../../OpenPGP.h"
#include "module.h"

namespace module {

const Module sign_timestamp(
    // name
    "sign-timestamp",

    // positional arguments
    {
        "signer-key",
        "passphrase",
        "seconds-since-epoch",
    },

    // optional arguments
    {
        std::make_pair("-h", std::make_pair("hash algorithm", "SHA1")),
    },

    // optional flags
    {
        std::make_pair("-a", std::make_pair("armored",          true)),
    },

    // function to run
    [](const std::map <std::string, std::string> & args,
       const std::map <std::string, bool>        & flags,
       std::ostream                              & out,
       std::ostream                              & err) -> int {
        std::ifstream signer_file(args.at("signer-key"), std::ios::binary);
        if (!signer_file){
            err << "IOError: File \"" + args.at("signer-key") + "\" not opened." << std::endl;
            return -1;
        }

        std::stringstream s(args.at("seconds-since-epoch"));
        uint32_t time;
        if (!(s >> time)){
            err << "Error: Invalid time." << std::endl;
            return -1;
        }

        if (OpenPGP::Hash::NUMBER.find(args.at("-h")) == OpenPGP::Hash::NUMBER.end()){
            err << "Error: Bad Hash Algorithm: " << args.at("-h") << std::endl;
            return -1;
        }

        const OpenPGP::Sign::Args signargs(OpenPGP::SecretKey(signer_file),
                                           args.at("passphrase"),
                                           4,
                                           OpenPGP::Hash::NUMBER.at(args.at("-h")));

            const OpenPGP::DetachedSignature timestamp = OpenPGP::Sign::timestamp(signargs, time);

        if (!timestamp.meaningful()){
            err << "Error: Generated bad timestamp signature." << std::endl;
            return -1;
        }

        out << timestamp.write(flags.at("-a")?OpenPGP::PGP::Armored::YES:OpenPGP::PGP::Armored::NO, OpenPGP::Packet::Tag::Format::NEW) << std::endl;
        return 0;
    }
);

}

#endif
