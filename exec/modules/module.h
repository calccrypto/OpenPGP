/*
module.h
Container for parsing commandline data and running function on given arguments

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

#ifndef __COMMAND__
#define __COMMAND__

#include <algorithm>
#include <cctype>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <vector>

namespace module {

class Module{
    public:
        typedef std::map <std::string, std::pair <std::string, std::string> > Args;
        typedef std::map <std::string, std::string>                           Flags;

    private:
        std::string name;                                                     // name of this module, and calling string; no whitespace
        std::vector <std::string> positional;                                 // postional arguments
        Args args;                                                            // option -> value
        Flags flags;                                                          // all values start as false; no chaining
        std::function <int(const std::map <std::string, std::string> &,
                           const std::map <std::string, bool>        &)> run; // function to run

        // constructor argument checks
        // throws if fail
        void check_name(const std::string & n) const;
        void check_positional(const std::vector <std::string> & pos) const;

        // check for whitespace in optional arguments
        template <typename Optional>
        void check_optional(const Optional & options) const{
            for(auto option : options){
                for(char const & c : option.first){
                    if (std::isspace(c)){
                        throw std::runtime_error("Error: Whitespace found in option: " + option.first);
                    }
                }
            }
        }

        // check if elements of rhs are already in lhs
        void check_duplicate(const Args & arg, const Flags & flag) const;
        void check_run(const std::function <int(std::map <std::string, std::string> &)> & func) const;

        // unknown arguments are ignored
        const char * parse(int argc, char * argv[],
                           std::map <std::string, std::string> & parsed_args,
                           std::map <std::string, bool>        & parsed_flags) const;

    public:
        Module() = default;                                         // no default constructor
        Module(const Module & cmd);
        Module(Module && cmd);
        Module(const std::string                                                      & n,
               const std::vector <std::string>                                        & pos,
               const Args                                                             & arg,
               const Flags                                                            & flag,
               const std::function <int(const std::map <std::string, std::string> &,
                                        const std::map <std::string, bool>        &)> & func);

        Module & operator=(const Module & cmd);
        Module & operator=(Module && cmd);

        const std::string & get_name() const;                       // can only get name out
        std::string help(const std::string & indent = "") const;    // get help string

        int operator()(int argc, char * argv[]) const;              // call operator() after setup
};

// Output data into a file, or if not possible, to std::cout
void output(const std::string & data, const std::string & filename = "");

}

#endif