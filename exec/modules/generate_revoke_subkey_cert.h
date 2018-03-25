/*
generate_revoke_subkey_cert.h
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

#ifndef __COMMAND_GENERATE_REVOKE_SUBKEY_CERT__
#define __COMMAND_GENERATE_REVOKE_SUBKEY_CERT__

#include "../../OpenPGP.h"
#include "module.h"

namespace module {

const Module generate_revoke_subkey_cert(
    // name
    "generate-revoke-subkey-cert",

    // positional arguments
    {
        "private-key",
        "passphrase",
    },

    // optional arguments
    {
        std::make_pair("-c", std::make_pair("code (0-3)",        "0")),
        std::make_pair("-r", std::make_pair("reason",             "")),
        std::make_pair("-h", std::make_pair("hash_algorithm", "SHA1")),
        std::make_pair("-k", std::make_pair("subkey ID to match", "")),
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
        std::ifstream key(args.at("private-key"), std::ios::binary);
        if (!key){
            err << "Error: File \"" + args.at("private-key") + "\" not opened." << std::endl;
            return -1;
        }

        unsigned int code;
        std::stringstream s(args.at("-c"));
        if (!(s >> code) || !OpenPGP::Subpacket::Tag2::Revoke::is_key_revocation(code)){
            err << "Error:: Bad Revocation Code: " << std::to_string(code) << std::endl;
            return -1;
        }

        if (OpenPGP::Hash::NUMBER.find(args.at("-h")) == OpenPGP::Hash::NUMBER.end()){
            err << "Error: Bad Hash Algorithm: " << args.at("-h") << std::endl;
            return -1;
        }

        const OpenPGP::SecretKey pri(key);
        const OpenPGP::Revoke::Args revargs(pri,
                                            args.at("passphrase"),
                                            pri,
                                            static_cast <uint8_t> (code),
                                            args.at("-r"),
                                            4,
                                            OpenPGP::Hash::NUMBER.at(args.at("-h")));

        const OpenPGP::RevocationCertificate cert = OpenPGP::Revoke::subkey_cert(revargs, args.at("-k"));

        if (!cert.meaningful()){
            err << "Error: Generated bad subkey revocation certificate." << std::endl;
            return -1;
        }

        out << cert.write(flags.at("-a")?OpenPGP::PGP::Armored::YES:OpenPGP::PGP::Armored::NO, OpenPGP::Packet::Tag::Format::NEW) << std::endl;
        return 0;
    }
);

}

#endif
