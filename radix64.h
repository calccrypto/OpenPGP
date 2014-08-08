/*
radix64.h
Radix-64 converter, as defined by OpenPGP in RFC 4880 sec 6

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

#ifndef __RADIX64__
#define __RADIX64__

#include <algorithm>
#include <iostream>

#include "common/includes.h"

// RFC 4880 sec 6.2 - max is 76 for OpenPGP
const unsigned int MAX_LINE_LENGTH = 64;

// RFC 4880 sec 6.3
std::string ascii2radix64(std::string str, char char62 = '\x2b', char char63 = '\x2f');

// RFC 4880 sec 6.4
std::string radix642ascii(std::string str, char char62 = '\x2b', char char63 = '\x2f');

// RFC 4880 sec 6.1
uint32_t crc24(const std::string & str);
#endif
