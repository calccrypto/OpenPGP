/*
generate_revoke_cert.h
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

#ifndef __COMMAND_GENERATE_REVOKE_CERT__
#define __COMMAND_GENERATE_REVOKE_CERT__

#include "../../OpenPGP.h"
#include "module.h"

namespace module {

const Module generate_revoke_cert(
    // name
    "generate-revoke-cert",

    // positional arguments
    {
        "private-key",
        "passphrase",
    },

    // optional arguments
    {
        std::make_pair("-o", std::make_pair("output file",        "")),
        std::make_pair("-c", std::make_pair("code (0-3)",        "0")),
        std::make_pair("-r", std::make_pair("reason",             "")),
        std::make_pair("-h", std::make_pair("hash_algorithm", "SHA1")),
    },

    // optional flags
    {
        std::make_pair("-a", "armored"),
        std::make_pair("-s", "revoke subkey instead of primary key"),
    },

    // function to run
    [](const std::map <std::string, std::string> & args,
       const std::map <std::string, bool>        & flags) -> int {
        std::ifstream key(args.at("private-key"), std::ios::binary);
        if (!key){
            std::cerr << "Error: File \"" + args.at("private-key") + "\" not opened." << std::endl;
            return -1;
        }

        unsigned int code;
        std::stringstream s(args.at("-c"));
        if (!(s >> code) || !Revoke::is_key_revocation(code)){
            std::cerr << "Error:: Bad Revocation Code: " << std::to_string(code) << std::endl;
            return -1;
        }

        if (Hash::NUMBER.find(args.at("-h")) == Hash::NUMBER.end()){
            std::cerr << "Error: Bad Hash Algorithm: " << args.at("-n") << std::endl;
            return -1;
        }

        const RevArgs revargs(PGPSecretKey(key),
                              args.at("passphrase"),
                              static_cast <uint8_t> (code),
                              args.at("-r"),
                              4,
                              Hash::NUMBER.at(args.at("-h")));
        std::string error;

        const PGPRevocationCertificate cert = revoke_key_cert(revargs, flags.at("-s")?Signature_Type::SUBKEY_REVOCATION_SIGNATURE:Signature_Type::KEY_REVOCATION_SIGNATURE, error);

        if (cert.meaningful(error)){
            output(cert.write(flags.at("-a")?PGP::Armored::YES:PGP::Armored::NO), args.at("-o"));
        }
        else{
            std::cerr << error << std::endl;
        }

        return 0;
    }
);

}

#endif