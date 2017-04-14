/*
encrypt_pka.h
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

#ifndef __COMMAND_ENCRYPT_PKA__
#define __COMMAND_ENCRYPT_PKA__

#include "../../OpenPGP.h"
#include "module.h"

namespace module {

const Module encrypt_pka(
    // name
    "encrypt-pka",

    // positional arguments
    {
        "public-key",
        "file",
    },

    // optional arguments
    {
        std::make_pair("-o",     std::make_pair("output file",                                      "")),
        std::make_pair("-c",     std::make_pair("compression (UNCOMPRESSED, ZIP, ZLIB, BZIP2)", "ZLIB")),
        std::make_pair("-p",     std::make_pair("passphrase for signing key",                       "")),
        std::make_pair("--sign", std::make_pair("private key file",                                 "")),
        std::make_pair("--sym",  std::make_pair("symmetric encryption algorithm",             "AES256")),
        std::make_pair("-h",     std::make_pair("hash_algorithm for signing",                   "SHA1")),
    },

    // optional flags
    {
        std::make_pair("-a",    std::make_pair("armored",                                         true)),
        std::make_pair("--mdc", std::make_pair("use mdc?",                                        true)),
    },

    // function to run
    [](const std::map <std::string, std::string> & args,
       const std::map <std::string, bool>        & flags) -> int {
        std::ifstream key(args.at("public-key"), std::ios::binary);
        if (!key){
            std::cerr << "Error: File \"" + args.at("public-key") + "\" not opened." << std::endl;
            return -1;
        }

        std::ifstream file(args.at("file"), std::ios::binary);
        if (!file){
            std::cerr << "Error: File \"" + args.at("file") + "\" not opened." << std::endl;
            return -1;
        }

        if (Hash::NUMBER.find(args.at("-h")) == Hash::NUMBER.end()){
            std::cerr << "Error: Bad Hash Algorithm: " << args.at("-h") << std::endl;
            return -1;
        }

        if (Compression::NUMBER.find(args.at("-c")) == Compression::NUMBER.end()){
            std::cerr << "Error: Bad Compression Algorithm: " << args.at("-c") << std::endl;
            return -1;
        }

        if (Sym::NUMBER.find(args.at("--sym")) == Sym::NUMBER.end()){
            std::cerr << "Error: Bad Symmetric Key Algorithm: " << args.at("--sym") << std::endl;
            return -1;
        }

        PGPSecretKey::Ptr signer = nullptr;
        if (args.at("--sign").size()){
            std::ifstream signing(args.at("--sign"), std::ios::binary);
            if (!signing){
                std::cerr << "Error: File \"" + args.at("--sign") + "\" not opened." << std::endl;
                return -1;
            }

            signer = std::make_shared <PGPSecretKey> (signing);

            std::string error;
            if (!signer -> meaningful(error)){
                std::cerr << "Error: Bad signing key.\n";
                return -1;
            }
        }

        const EncryptArgs encryptargs(args.at("file"),
                                      std::string(std::istreambuf_iterator <char> (file), {}),
                                      Sym::NUMBER.at(args.at("--sym")),
                                      Compression::NUMBER.at(args.at("-c")),
                                      flags.at("--mdc"),
                                      signer,
                                      args.at("-p"),
                                      Hash::NUMBER.at(args.at("-h")));
        std::string error;

        const PGPMessage encrypted = ::encrypt_pka(encryptargs, PGPPublicKey(key), error);

        if (encrypted.meaningful(error)){
            output(encrypted.write(flags.at("-a")?PGP::Armored::YES:PGP::Armored::NO, Packet::Format::NEW), args.at("-o"));
        }
        else{
            std::cerr << error << std::endl;
        }

        return 0;
    }
);

}

#endif