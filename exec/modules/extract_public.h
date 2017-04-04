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
        std::make_pair("-o", std::make_pair("output file", "")),
    },

    // optional flags
    {
        std::make_pair("-a", std::make_pair("armored",   true)),
    },

    // function to run
    [](const std::map <std::string, std::string> & args,
       const std::map <std::string, bool>        & flags) -> int {
        std::ifstream key(args.at("private-key"), std::ios::binary);
        if (!key){
            std::cerr << "IOError: File \"" + args.at("private-key") + "\" not opened." << std::endl;
            return -1;
        }

        const PGPSecretKey pri(key);
        std::string error;

        if (pri.meaningful(error)){
            output(pri.get_public().write(flags.at("-a")?PGP::Armored::YES:PGP::Armored::NO, Packet::Format::NEW), args.at("-o"));
        }
        else{
            std::cerr << error << std::endl;
        }

        return 0;
    }
);

}

#endif