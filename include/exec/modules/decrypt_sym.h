/*
decrypt_sym.h
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

#ifndef __COMMAND_DECRYPT_SYM__
#define __COMMAND_DECRYPT_SYM__

#include "../../OpenPGP.h"
#include "module.h"

namespace module {

const Module decrypt_sym(
    // name
    "decrypt-sym",

    // positional arguments
    {
        "file",
        "passphrase",
    },

    // optional arguments
    {
        std::make_pair("-s", std::make_pair("signing public key",  "")),
    },

    // optional flags
    {

    },

    // function to run
    [](const std::map <std::string, std::string> & args,
       const std::map <std::string, bool>        & flags,
       std::ostream                              & out,
       std::ostream                              & err) -> int {
        std::ifstream msg(args.at("file"), std::ios::binary);
        if (!msg){
            err << "Error: File \"" + args.at("file") + "\" not opened." << std::endl;
            return -1;
        }

        OpenPGP::Key::Ptr signer = nullptr;
        if (args.at("-s").size()){
            std::ifstream s(args.at("-s"), std::ios::binary);
            if (!s){
                err << "Error: File \"" + args.at("-s") + "\" not opened." << std::endl;
                return -1;
            }

            signer = std::make_shared <OpenPGP::PublicKey> (s);

            if (!signer -> meaningful()){
                err << "Error: Bad signing key.\n";
                return -1;
            }
        }

        const OpenPGP::Message message(msg);
        const OpenPGP::Message decrypted = OpenPGP::Decrypt::sym(message, args.at("passphrase"));

        if (!decrypted.meaningful()){
            err << "Error: Decrypted data is not meaningful." << std::endl;
            return -1;
        }

        // extract data
        std::string cleartext = "";
        for(OpenPGP::Packet::Tag::Ptr const & p : decrypted.get_packets()){
            if (p -> get_tag() == OpenPGP::Packet::LITERAL_DATA){
                cleartext += std::static_pointer_cast <OpenPGP::Packet::Tag11> (p) -> out(false);
            }
        }

        cleartext += "\n\n";

        // if signing key provided, check the signature
        if (signer){
            const int verified = OpenPGP::Verify::binary(*signer, decrypted);
            if (verified == -1){
                err << "Warning: Verification failure.\n" << std::endl;
            }

            cleartext += "Message was" + std::string((verified == 1)?"":" not") + " signed by \"" + args.at("-s") + "\" (" + hexlify(signer -> keyid()) + ").\n";
        }
        // otherwise, just list attached signatures
        else{
            for(OpenPGP::Packet::Tag::Ptr const & p : decrypted.get_packets()){
                if (p -> get_tag() == OpenPGP::Packet::SIGNATURE){
                    cleartext += "Unverified signature from " + hexlify(std::static_pointer_cast <OpenPGP::Packet::Tag2> (p) -> get_keyid()) + " found.\n";
                }
            }
        }

        out << cleartext << std::endl;
        return 0;
    }
);

}

#endif
