/*
revoke_with_cert.h
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

#ifndef __COMMAND_REVOKE_WITH_CERT__
#define __COMMAND_REVOKE_WITH_CERT__

#include "../../OpenPGP.h"
#include "module.h"

namespace module {

const Module revoke_with_cert(
    // name
    "revoke-with-cert",

    // positional arguments
    {
        "target",
        "revocation-certificate",
    },

    // optional arguments
    {

    },

    // optional flags
    {
        std::make_pair("-a", std::make_pair("armored",   true)),
    },

    // function to run
    [](const std::map <std::string, std::string> & args,
       const std::map <std::string, bool>        & flags,
       std::ostream                              & out,
       std::ostream                              & err) -> int {
        std::ifstream target(args.at("target"), std::ios::binary);
        if (!target){
            err << "IOError: File \"" + args.at("target") + "\" not opened." << std::endl;
            return -1;
        }

        std::ifstream cert(args.at("revocation-certificate"), std::ios::binary);
        if (!cert){
            err << "IOError: File \"" + args.at("revocation-certificate") + "\" not opened." << std::endl;
            return -1;
        }

        const OpenPGP::Key key(target);
        const OpenPGP::RevocationCertificate rev(cert);

        const OpenPGP::PublicKey revoked = OpenPGP::Revoke::with_cert(key, rev);

        if (!revoked.meaningful()){
            err << "Error: Generated bad revoked key." << std::endl;
            return -1;
        }

        out << revoked.write(flags.at("-a")?OpenPGP::PGP::Armored::YES:OpenPGP::PGP::Armored::NO, OpenPGP::Packet::Tag::Format::NEW) << std::endl;
        return 0;
    }
);

}
#endif
