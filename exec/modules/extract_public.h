#ifndef __COMMAND_EXTRACT_PUBLIC__
#define __COMMAND_EXTRACT_PUBLIC__

#include "../../OpenPGP.h"
#include "module.h"

namespace module {

const Module extract_public(
    // name
    "extract-public",

    // positional arguments
    {
        "private-key",
    },

    // optional arugments
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
        std::ifstream key(args.at("private-key"), std::ios::binary);
        if (!key){
            err << "IOError: File \"" + args.at("private-key") + "\" not opened." << std::endl;
            return -1;
        }

        const OpenPGP::SecretKey pri(key);
        if (!pri.meaningful()){
            err << "Error: Key is not meaningful." << std::endl;
            return -1;
        }

        out << pri.get_public().write(flags.at("-a")?OpenPGP::PGP::Armored::YES:OpenPGP::PGP::Armored::NO, OpenPGP::Packet::Tag::Format::NEW) << std::endl;
        return 0;
    }
);

}

#endif
