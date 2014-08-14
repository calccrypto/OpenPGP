/*
Tag8.h
Compressed Data Packet

Copyright (c) 2013, 2014 Jason Lee

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

#ifndef __TAG8__
#define __TAG8__

#include "../Compress/Compress.h"
#include "packet.h"

class Tag8 : public Packet{
    private:

        /*
        Compression Algorithm values:
            0 - uncompressed (default)
            1 - ZIP
            2 - ZLIB
            3 - BZip2
        */

        uint8_t comp;
        std::string compressed_data;

        std::string compress(const std::string & data);
        std::string decompress(const std::string & data);

        std::string show_title() const;

    public:
        typedef std::shared_ptr <Tag8> Ptr;

        Tag8();
        Tag8(std::string & data);
        void read(std::string & data, const uint8_t part = 0);
        std::string show(const uint8_t indents = 0, const uint8_t indent_size = 4) const;
        std::string raw() const;

        uint8_t get_comp() const;                           // get compression algorithm
        std::string get_data() const;                       // get uncompressed data
        std::string get_compressed_data() const;            // get compressed data

        void set_comp(const uint8_t c);                     // set compression algorithm
        void set_data(const std::string & data);            // set uncompressed data
        void set_compressed_data(const std::string & data); // set compressed data

        Packet::Ptr clone() const;
};
#endif
