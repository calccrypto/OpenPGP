/*
main.cpp
OpenPGP executable

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

#include <iostream>
#include <map>
#include <sstream>
#include <vector>

#include "modules/modules.h"

std::string::size_type help(const std::string & match = "",
                            const bool show_header    = false,
                            std::ostream & stream     = std::cout,
                            std::string indent        = ""){
    if (show_header){
        stream << indent << "An OpenPGP implementation (RFC 4880)\n"
               << indent << "by Jason Lee @ calccrypto at gmail.com\n\n"
               << indent << "All optional flags default to false\n\n"
               << indent << "    help - print all modules\n"
               << std::endl;
        indent += "    ";
    }

    std::string::size_type found = 0;
    for(module::Module const & cmd : module::ordered){
        if (cmd.get_name().substr(0, match.size()) == match){
            stream << cmd.help(indent) << std::endl;
            found++;
        }
    }

    return found;
}

int main(int argc, char * argv[]){
    if (argc == 1){
        return help("", true);
    }

    // if requesting help
    if (!std::strncmp(argv[1],"help", 4)){
        if (argc == 2){
            help("", true);
        }
        else{
            help(argv[2], false);
        }
        return 0;
    }

    // reverse the mapping for commands
    std::map <std::string, std::vector <module::Module>::size_type> mapping;
    for(std::vector <module::Module>::size_type i = 0; i < module::ordered.size(); i++){
        mapping[module::ordered[i].get_name()] = i;
    }

    // find module
    std::map <std::string, std::vector <module::Module>::size_type>::iterator it = mapping.find(argv[1]);

    // if module not found, try suggestions
    if (it == mapping.end()){
        std::cerr << "Error: Function " << argv[1] << " not found." << std::endl;
        std::stringstream s;
        if (help(argv[1], false, s, "    ")){
            std::cout << "Possible matches:\n" << s.str() << std::endl;
        }
        return -1;
    }

    // run module
    return module::ordered.at(it -> second)(argc - 2, argv + 2);
}
