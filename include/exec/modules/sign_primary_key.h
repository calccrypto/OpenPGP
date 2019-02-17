/*
sign_key.h
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

#ifndef __COMMAND_SIGN_PRIMARY_KEY__
#define __COMMAND_SIGN_PRIMARY_KEY__

#include "../../OpenPGP.h"
#include "module.h"

namespace module {

const Module sign_primary_key(
    // name
    "sign-primary-key",

    // positional arguments
    {
        "signer-key",
        "passphrase",
        "signee-key",
    },

    // optional arguments
    {
        std::make_pair("-c", std::make_pair("certification level (0x10 - 0x13 without '0x')",   "13")),
        std::make_pair("-h", std::make_pair("hash algorithm",                                 "SHA1")),
        std::make_pair("-u", std::make_pair("user to certify",                                    "")),
    },

    // optional flags
    {
        std::make_pair("-a", std::make_pair("armored",                                          true)),
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

        std::ifstream signee_file(args.at("signee-key"), std::ios::binary);
        if (!signee_file){
            err << "IOError: File \"" + args.at("signee-key") + "\" not opened." << std::endl;
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

        const OpenPGP::PublicKey key = OpenPGP::Sign::primary_key(signargs, OpenPGP::PublicKey(signee_file), args.at("-u"), OpenPGP::mpitoulong(OpenPGP::hextompi(args.at("-c"))));

        if (!key.meaningful()){
            err << "Error: Generated bad primary key signature." << std::endl;
            return -1;
        }

        out << key.write(flags.at("-a")?OpenPGP::PGP::Armored::YES:OpenPGP::PGP::Armored::NO, OpenPGP::Packet::Tag::Format::NEW) << std::endl;
        return 0;
    }
);

}

#endif
