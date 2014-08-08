/*
pgpbzip2.h
BZIP2 compression and decompression with strings

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

#include <assert.h>
#include <bzlib.h>
#include <iostream>
#include <sstream>
#include <stdexcept>

const unsigned int bz2_BUFFER_SIZE = 4096 * sizeof(char);   // size of buffer
const unsigned int bz2_BLOCKSIZE100K = 9;                   // 1 - 9; 9 = best compression
const unsigned int bz2_VERBOSITY = 0;                       // 0 - 4; 0 = silent
const unsigned int bz2_WORKFACTOR = 0;                      // 0 - 250; 0 = 30
const unsigned int bz2_SMALL = 0;                           // 0 or 1

int bz2_compress(const std::string & src, std::string & dst);
int bz2_decompress(const std::string & src, std::string & dst);
