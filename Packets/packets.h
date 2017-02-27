/*
packets.h
Main packets and related functions include file

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

#ifndef __PACKETS__
#define __PACKETS__

#include "packet.h"

#include "Partial.h"
#include "Tag0.h"
#include "Tag1.h"
#include "Tag2.h"
#include "Tag3.h"
#include "Tag4.h"
#include "Tag5.h"
#include "Tag6.h"
#include "Tag7.h"
#include "Tag8.h"
#include "Tag9.h"
#include "Tag10.h"
#include "Tag11.h"
#include "Tag12.h"
#include "Tag13.h"
#include "Tag14.h"
#include "Tag17.h"
#include "Tag18.h"
#include "Tag19.h"
#include "Tag60.h"
#include "Tag61.h"
#include "Tag62.h"
#include "Tag63.h"

// Functions that are needed globally and cannot be placed inside Packet class

// calculates the length of a partial body
unsigned int partialBodyLen(uint8_t first_octet);

// reads and removes packet header, returning the raw packet data. Input data is shortened
std::string read_packet_header(std::string & data, uint8_t & tag, bool & format, uint8_t & partial);

// parses raw packet data
Packet::Ptr read_packet_raw(const bool format, const uint8_t tag, uint8_t & partial, std::string & packet_data);

// parse packet with header; wrapper for read_packet_header and read_packet_raw
// partial should be initialized with 0
Packet::Ptr read_packet(std::string & data, uint8_t & partial);
#endif
