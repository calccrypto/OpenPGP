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
        std::make_pair("-o",     std::make_pair("output file",                                                   "")),
        std::make_pair("-c",     std::make_pair("compression (Uncompressed, ZIP (DEFLATE), ZLIB, BZIP2)",    "ZLIB")),
        std::make_pair("-p",     std::make_pair("passphrase for signing key",                                    "")),
        std::make_pair("--sign", std::make_pair("private key file",                                              "")),
        std::make_pair("--sym",  std::make_pair("symmetric encryption algorithm",                          "AES256")),
    },

    // optional flags
    {
        std::make_pair("-a",    "armored"),
        std::make_pair("-d",    "delete original"),
        std::make_pair("--mdc", "use mdc?"),
    },

    // function to run
    [](const std::map <std::string, std::string> & args,
       const std::map <std::string, bool>        & flags) -> int {
        std::ifstream key(args.at("public-key"), std::ios::binary);
        if (!key){
            std::cerr << "Error: File '" + args.at("public-key") + "' not opened." << std::endl;
            return -1;
        }

        std::ifstream file(args.at("file"), std::ios::binary);
        if (!file){
            std::cerr << "Error: File '" + args.at("file") + "' not opened." << std::endl;
            return -1;
        }

        if (Compression::Number.find(args.at("-c")) == Compression::Number.end()){
            std::cerr << "Error: Bad Compression Algorithm: " << args.at("-c") << std::endl;
            return -1;
        }

        if (Sym::Number.find(args.at("--sym")) == Sym::Number.end()){
            std::cerr << "Error: Bad Symmetric Key Algorithm: " << args.at("--sym") << std::endl;
            return -1;
        }

        PGPSecretKey::Ptr signer = nullptr;
        if (args.at("--sign").size()){
            if (args.find("p") == args.end()){ // need to check whether or not "-p" was used, not whether or not the passphrase is an empty string
                std::cerr << "Error: Option \"-p\" and singer passphrase needed." << std::endl;
                return -1;
            }

            std::ifstream signing(args.at("--sign"), std::ios::binary);
            if (!signing){
                std::cerr << "Error: File '" + args.at("--sign") + "' not opened." << std::endl;
                return -1;
            }

            signer = std::make_shared <PGPSecretKey> (signing);
        }
        else{
            if (args.find("-p") != args.end()){
                std::cerr << "Warning: Passphrase provided without a Signing Key. Ignored." << std::endl;
            }
        }

        output(::encrypt_pka(PGPPublicKey(key),
                             std::string(std::istreambuf_iterator <char> (file), {}),
                             args.at("file"),
                             Sym::Number.at(args.at("-sym")),
                             Compression::Number.at(args.at("-c")),
                             flags.at("--mdc"),
                             signer,
                             args.at("-p")).write(flags.at("-a")), args.at("-o"));

        if (flags.at("-d")){
            remove(args.at("file").c_str());
        }

        return 0;
    }
);

}

#endif