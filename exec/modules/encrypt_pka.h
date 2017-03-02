/*
encrypt_pka.h
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

    // optional arugments
    {
        std::make_pair("o",    std::make_pair("output file",                                                   "")),
        std::make_pair("a",    std::make_pair("armored",                                                      "t")),
        std::make_pair("c",    std::make_pair("compression (Uncompressed, ZIP (DEFLATE), ZLIB, BZIP2)",    "ZLIB")),
        std::make_pair("d",    std::make_pair("delete original",                                              "f")),
        std::make_pair("mdc",  std::make_pair("use mdc?",                                                     "t")),
        std::make_pair("p",    std::make_pair("passphrase for signing key",                                    "")),
        std::make_pair("sign", std::make_pair("private key file",                                              "")),
        std::make_pair("sym",  std::make_pair("symmetric encryption algorithm",                          "AES256")),
    },

    // function to run
    [](std::map <std::string, std::string> & args) -> int {
        std::ifstream k(args.at("public-key"), std::ios::binary);
        if (!k){
            std::cerr << "Error: File '" + args.at("public-key") + "' not opened." << std::endl;
            return -1;
        }

        std::ifstream d(args.at("file"), std::ios::binary);
        if (!d){
            std::cerr << "Error: File '" + args.at("file") + "' not opened." << std::endl;
            return -1;
        }

        args["-a"] = lower(args.at("a"));
        args["-c"] = upper(args.at("c"));
        args["-d"] = lower(args.at("d"));
        args["-mdc"] = lower(args.at("mdc"));
        args["-sym"] = upper(args.at("sym"));

        if (Compression_Numbers.find(args.at("c")) == Compression_Numbers.end()){
            std::cerr << "Error: Bad Compression Algorithm Number" << std::endl;
            return -1;
        }

        if (Symmetric_Algorithms_Numbers.find(args.at("sym")) == Symmetric_Algorithms_Numbers.end()){
            std::cerr << "Error: Bad Symmetric Key Algorithm Number" << std::endl;
            return -1;
        }

        PGPSecretKey::Ptr signer = nullptr;
        if (args.at("sign").size()){
            if (args.find("-p") == args.end()){ // need to check whether or not "-p" was used, not whether or not the passphrase is an empty string
                std::cerr << "Error: Option \"-p\" and singer passphrase needed." << std::endl;
                return -1;
            }

            std::ifstream signing(args.at("sign"), std::ios::binary);
            if (!signing){
                std::cerr << "Error: File '" + args.at("sign") + "' not opened." << std::endl;
                return -1;
            }

            signer = std::make_shared <PGPSecretKey> (signing);
        }
        else {
            if (args.find("-p") != args.end()){
                std::cerr << "Warning: Passphrase provided without a Signing Key. Ignored." << std::endl;
            }
        }

        std::stringstream s;
        s << d.rdbuf();

        PGPPublicKey pub(k);

        output(::encrypt_pka(pub, s.str(), args.at("file"), Symmetric_Algorithms_Numbers.at(args.at("sym")), Compression_Numbers.at(args.at("c")), (args.at("mdc") == "t"),  signer, args.at("p")).write((args.at("a") == "f")?1:(args.at("a") == "t")?2:0), args.at("o"));

        if (((args.at("f") == "t") || (args.at("f") == "b")) && (args.at("d") == "t")){
            remove(args.at("file").c_str());
        }

        return 0;
    }
);

}

#endif