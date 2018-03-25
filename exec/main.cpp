/*
main.cpp
OpenPGP executable

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

#include <iostream>
#include <map>
#include <regex>
#include <sstream>
#include <vector>

#include "modules/modules.h"

std::ostream & show_header(std::ostream & stream = std::cout,
                           std::string indent    = ""){
    return stream << indent << "An OpenPGP implementation (RFC 4880)\n"
                  << indent << "by Jason Lee @ calccrypto at gmail.com\n\n"
                  << indent << "    help [module name] - print all modules with matching name\n"
                  << std::endl;
}

std::size_t help(const std::string & match        = "",
                            std::ostream & stream = std::cout,
                            std::string indent    = ""){
    const std::regex regex(match);
    std::size_t found = 0;
    for(module::Module const & cmd : module::ordered){
        if (std::regex_search(cmd.get_name(), regex)){
            stream << cmd.help(indent) << std::endl;
            found++;
        }
    }

    return found;
}

int main(int argc, char * argv[]){
    if (argc == 1){
        show_header(std::cout);
        help("", std::cout, "    ");
        return 0;
    }

    // if requesting help
    if (!std::strncmp(argv[1], "help", 4)){
        if (argc == 2){
            show_header(std::cout);
            help("", std::cout, "    ");
        }
        else{
            std::stringstream s;
            const std::size_t found = help(argv[2], s, "    ");
            std::cout << found << " matches for \"" << argv[2] << "\"";
            if (found){
                std::cout << ":\n" << s.str() << std::flush;
            }
            else{
                std::cout << std::endl;
            }
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
        std::cerr << "Error: Function \"" << argv[1] << "\" not found." << std::endl;
        std::stringstream s;
        const std::size_t found = help(argv[1], s, "    ");
        if (found){
            std::cout << found << " matches:\n" << s.str() << std::flush;
        }
        return -1;
    }

    // run module
    return module::ordered.at(it -> second)(argc - 2, argv + 2);
}
