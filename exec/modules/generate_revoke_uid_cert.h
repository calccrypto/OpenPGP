/*
generate_revoke_uid_cert.h
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

#ifndef __COMMAND_GENERATE_REVOKE_UID_CERT__
#define __COMMAND_GENERATE_REVOKE_UID_CERT__

#include "../../OpenPGP.h"
#include "module.h"

namespace module {

const Module generate_revoke_uid_cert(
    // name
    "generate-revoke-uid-cert",

    // positional arguments
    {
        "private-key",
        "passphrase",
    },

    // optional arguments
    {
        std::make_pair("-r", std::make_pair("reason",             "")),
        std::make_pair("-h", std::make_pair("hash_algorithm", "SHA1")),
        std::make_pair("-u", std::make_pair("User ID to match",   "")),
    },

    // optional flags
    {
        std::make_pair("-a", std::make_pair("armored",          true)),
    },

    // function to run
    [](const std::map <std::string, std::string> & args,
       const std::map <std::string, bool>        & flags) -> int {
        std::ifstream key(args.at("private-key"), std::ios::binary);
        if (!key){
            std::cerr << "Error: File \"" + args.at("private-key") + "\" not opened." << std::endl;
            return -1;
        }

        if (Hash::NUMBER.find(args.at("-h")) == Hash::NUMBER.end()){
            std::cerr << "Error: Bad Hash Algorithm: " << args.at("-h") << std::endl;
            return -1;
        }

        const PGPSecretKey pri(key);
        const RevArgs revargs(pri,
                              args.at("passphrase"),
                              pri,
                              Revoke::USER_ID_INFORMATION_IS_NO_LONGER_VALID,
                              args.at("-r"),
                              4,
                              Hash::NUMBER.at(args.at("-h")));
        std::string error;

        const PGPRevocationCertificate cert = ::revoke_uid_cert(revargs, args.at("-u"), error);

        if (cert.meaningful(error)){
            std::cout << cert.write(flags.at("-a")?PGP::Armored::YES:PGP::Armored::NO, Packet::Format::NEW) << std::endl;;
        }
        else{
            std::cerr << error << std::endl;
        }

        return 0;
    }
);

}

#endif