/*
fingerprint.h
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

#ifndef __COMMAND_FINGERPRINT__
#define __COMMAND_FINGERPRINT__

#include "../../OpenPGP.h"
#include "module.h"

namespace module {

const Module fingerprint(
    // name
    "fingerprint",

    // positional arguments
    {
        "key-file",
    },

    // optional arguments
    {
        std::make_pair("-s", std::make_pair("separator",                       ":")),
        std::make_pair("-g", std::make_pair("group this many octets together", "1")),
    },

    // optional flags
    {

    },

    // function to run
    [](const std::map <std::string, std::string> & args,
       const std::map <std::string, bool>        & flags,
       std::ostream                              & out,
       std::ostream                              & err) -> int {
        std::ifstream f(args.at("key-file"), std::ios::binary);
        if (!f){
            err << "Error: File \"" << args.at("key-file") << "\" not opened." << std::endl;
            return -1;
        }

        std::stringstream s(args.at("-g"));
        std::string::size_type split;
        if (!(s >> split)){
            err << "Error: Bad split size." << std::endl;
            return -1;
        }

        const OpenPGP::Key key(f);

        if (!key.meaningful()){
            err << "Error: Key is not meaningful." << std::endl;
            return -1;
        }

        const std::string fp = key.fingerprint();

        std::string separated;

        if (split){
            const std::string sep = args.at("-s");

            // insert separator
            for(std::string::size_type i = 0; (i + split) < fp.size(); i += split){
                separated += hexlify(fp.substr(i, split)) + sep;
            }

            std::string::size_type rem = fp.size() % split;
            if (!rem || (split == 1)){
                rem = split;
            }

            separated += hexlify(fp.substr(fp.size() - rem, rem));
        }
        else{
            separated = hexlify(fp);
        }

        out << separated << std::endl;
        return 0;
    }
);

}

#endif
