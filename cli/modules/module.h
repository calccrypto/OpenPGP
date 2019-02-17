/*
module.h
Container for parsing commandline data and running function on given arguments

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
        // Optional arguments with default values
        // name -> <explaination, default value>
        typedef std::map <std::string, std::pair <std::string, std::string> >    Opts;

        // optional arguments that default to true and false only
        // flags used flip default value
        // name -> <explaination, true/false>
        typedef std::map <std::string, std::pair <std::string, bool> >           Flags;

        // function to check arguments and run user defined actions
        typedef std::function <int(const std::map <std::string, std::string> &,
                                   const std::map <std::string, bool>        &,
                                   std::ostream                              &,
                                   std::ostream                              &)> Run;

    private:
        std::string name;                       // name of this module, and calling string; no whitespace
        std::vector <std::string> positional;   // required postional arguments (no default value)
        Opts opts;                              // optional arguments (default value provided)
        Flags flags;                            // boolean arguments  (default value provided)
        Run run;                                // function to run

        // check for whitespace in names; throws if fail
        void check_names_ws() const;

        // check if there are any duplicate argument names; throws if fail
        void check_duplicate() const;

        // unknown arguments are ignored
        const char * parse(int argc, char * argv[],
                           std::map <std::string, std::string> & parsed_args,
                           std::map <std::string, bool>        & parsed_flags) const;

    public:
        Module() = default;                                         // no default constructor
        Module(const Module & cmd);
        Module(Module && cmd);
        Module(const std::string                & n,
               const std::vector <std::string>  & pos,
               const Opts                       & opts,
               const Flags                      & flag,
               const Run                        & func);

        Module & operator=(const Module & cmd);
        Module & operator=(Module && cmd);

        const std::string & get_name() const;                       // can only get name out
        std::string help(const std::string & indent = "") const;    // get help string

        // call operator() after setup
        int operator()(int argc, char * argv[],
                       std::ostream & out = std::cout,
                       std::ostream & err = std::cerr) const;
};

}

#endif
