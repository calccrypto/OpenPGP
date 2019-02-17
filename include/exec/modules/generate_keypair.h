/*
gemerate_key_pair.h
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

#ifndef __COMMAND_GENERATE_KEYPAIR__
#define __COMMAND_GENERATE_KEYPAIR__

#include <cstdlib>
#include <fstream>

#include "../../OpenPGP.h"
#include "module.h"

namespace module {

const Module generate_keypair(
    // name
    "generate-keypair",

    // positional arguments
    {

    },

    // optional arguments
    {
        std::make_pair("-o",         std::make_pair("prefix of output files",                               "key")),
        std::make_pair("-p",         std::make_pair("passphase",                                               "")),
        std::make_pair("-u",         std::make_pair("username",                                                "")),
        std::make_pair("-c",         std::make_pair("comment",                                                 "")),
        std::make_pair("-e",         std::make_pair("email",                                                   "")),

        std::make_pair("--ppka",     std::make_pair("Primary Key PKA",                      "RSA_ENCRYPT_OR_SIGN")),
        std::make_pair("--pkeysize", std::make_pair("Primary PKA Key size in bits",                        "2048")),
        std::make_pair("--psym",     std::make_pair("Primary Key S2K Symmetric Key Algorithm",           "AES256")),
        std::make_pair("--phash",    std::make_pair("Primary Key S2K Hash Algorithm",                      "SHA1")),
        std::make_pair("--psig",     std::make_pair("Primary Key Signature Hash Algorithm",                "SHA1")),

        std::make_pair("--spka",     std::make_pair("Subkey PKA",                           "RSA_ENCRYPT_OR_SIGN")),
        std::make_pair("--skeysize", std::make_pair("Subkey PKA size in bits",                             "2048")),
        std::make_pair("--ssym",     std::make_pair("Subkey S2K Symmetric Key Algorithm",                "AES256")),
        std::make_pair("--shash",    std::make_pair("Subkey S2K Hash Algorithm",                           "SHA1")),
        std::make_pair("--ssig",     std::make_pair("Subkey Signature Hash Algorithm",                     "SHA1")),
    },

    // optional flags
    {
        std::make_pair("-a",         std::make_pair("armored",                                               true)),
    },

    // function to run
    [](const std::map <std::string, std::string> & args,
       const std::map <std::string, bool>        & flags,
       std::ostream                              & out,
       std::ostream                              & err) -> int {
        if (OpenPGP::PKA::NUMBER.find(args.at("--ppka")) == OpenPGP::PKA::NUMBER.end()){
            err << "Error: Bad Public Key Algorithm: " << args.at("--pka") << std::endl;
            return -1;
        }

        if (OpenPGP::Sym::NUMBER.find(args.at("--psym")) == OpenPGP::Sym::NUMBER.end()){
            err << "Error: Bad Symmetric Key Algorithm: " << args.at("--psym") << std::endl;
            return -1;
        }

        if (OpenPGP::Hash::NUMBER.find(args.at("--phash")) == OpenPGP::Hash::NUMBER.end()){
            err << "Error: Bad Hash Algorithm: " << args.at("--phash") << std::endl;
            return -1;
        }

        if (OpenPGP::Hash::NUMBER.find(args.at("--psig")) == OpenPGP::Hash::NUMBER.end()){
            err << "Error: Bad Hash Algorithm: " << args.at("--psig") << std::endl;
            return -1;
        }

        if (OpenPGP::PKA::NUMBER.find(args.at("--spka")) == OpenPGP::PKA::NUMBER.end()){
            err << "Error: Bad Public Key Algorithm: " << args.at("--ska") << std::endl;
            return -1;
        }

        if (OpenPGP::Sym::NUMBER.find(args.at("--ssym")) == OpenPGP::Sym::NUMBER.end()){
            err << "Error: Bad Symmetric Key Algorithm: " << args.at("--ssym") << std::endl;
            return -1;
        }

        if (OpenPGP::Hash::NUMBER.find(args.at("--shash")) == OpenPGP::Hash::NUMBER.end()){
            err << "Error: Bad Hash Algorithm: " << args.at("--shash") << std::endl;
            return -1;
        }

        if (OpenPGP::Hash::NUMBER.find(args.at("--ssig")) == OpenPGP::Hash::NUMBER.end()){
            err << "Error: Bad Hash Algorithm: " << args.at("--ssig") << std::endl;
            return -1;
        }

        OpenPGP::KeyGen::Config config;
        config.passphrase = args.at("-p");
        config.pka        = OpenPGP::PKA::NUMBER.at(args.at("--ppka"));
        config.bits       = std::strtoul(args.at("--pkeysize").c_str(), 0, 10);
        config.sym        = OpenPGP::Sym::NUMBER.at(args.at("--psym"));
        config.hash       = OpenPGP::Hash::NUMBER.at(args.at("--phash"));

        OpenPGP::KeyGen::Config::UserID uid;
        uid.user          = args.at("-u");
        uid.comment       = args.at("-c");
        uid.email         = args.at("-e");
        uid.sig           = OpenPGP::Hash::NUMBER.at(args.at("--psig"));
        config.uids.push_back(uid);

        OpenPGP::KeyGen::Config::SubkeyGen subkey;
        subkey.pka        = OpenPGP::PKA::NUMBER.at(args.at("--spka"));
        subkey.bits       = std::strtoul(args.at("--skeysize").c_str(), 0, 10);
        subkey.sym        = OpenPGP::Sym::NUMBER.at(args.at("--ssym"));
        subkey.hash       = OpenPGP::Hash::NUMBER.at(args.at("--shash"));
        subkey.sig        = OpenPGP::Hash::NUMBER.at(args.at("--ssig"));
        config.subkeys.push_back(subkey);

        const OpenPGP::SecretKey pri = OpenPGP::KeyGen::generate_key(config);

        if (!pri.meaningful()){
            err << "Error: Generated bad keypair." << std::endl;
            return -1;
        }

        const OpenPGP::PublicKey pub = pri.get_public();

        const std::string pub_name = args.at("-o") + ".public";
        const std::string pri_name = args.at("-o") + ".private";

        std::ofstream pub_out(pub_name, std::ios::binary);
        if (!pub_out){
            err << "Error: Could not open public key file '" << pub_name << "' for writing." << std::endl;
            return -1;
        }

        std::ofstream pri_out(pri_name, std::ios::binary);
        if (!pri_out){
            err << "Error: Could not open private key file '" << pri_name << "' for writing." << std::endl;
            return -1;
        }

        pub_out << pub.write(flags.at("-a")?OpenPGP::PGP::Armored::YES:OpenPGP::PGP::Armored::NO, OpenPGP::Packet::Tag::Format::NEW) << std::flush;
        pri_out << pri.write(flags.at("-a")?OpenPGP::PGP::Armored::YES:OpenPGP::PGP::Armored::NO, OpenPGP::Packet::Tag::Format::NEW) << std::flush;

        out << "Keys written to '" << pub_name << "' and '" << pri_name << "'." << std::endl;
        return 0;
    }
);

}

#endif
