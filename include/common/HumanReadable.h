/*
HumanReadable.h
Fake stream that prepends indentations and appends newlines for printing.

Copyright (c) 2013 - 2019 Jason Lee @ calccrypto at gmail.com

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

#ifndef __HUMAN_READABLE__
#define __HUMAN_READABLE__

#include <string>
#include <sstream>

class HumanReadable {
    private:
        const std::string indent;
        const std::string prefix;
        std::stringstream data;
        std::size_t level;             // 0 is root

    protected:
        virtual std::string duplicate_string(const std::string & src, const std::size_t times) const;

    public:
        enum Move {
            UP,
            DOWN
        };

        // generate a prefix using the indentation character
        // depth sets how many indentations the prefix is made of
        // however, the current level is assumed to be 0
        HumanReadable(const std::size_t indent_size, const std::size_t depth = 0, const char indent_char = ' ');

        // user provided prefix
        HumanReadable(const std::string & prefix, const std::string & indent);

        std::size_t up();            // goes one level less deep (level - 1, up to 0)
        std::size_t down();          // goes one level deeper    (level + 1)

        std::size_t curr_level() const;
        std::string get() const;

        HumanReadable & operator<<(const std::string & str);
        HumanReadable & operator<<(const Move dir);
};

std::ostream & operator<<(std::ostream & stream, const HumanReadable & hr);

#endif
