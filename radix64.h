/*
Radix-64 converter, as defined by OpenPGP in RFC 4880
*/

#include <algorithm>
#include <iostream>

#include "common/includes.h"

#ifndef __RADIX64__
#define __RADIX64__
// RFC 4880 sec 6.3
std::string ascii2radix64(std::string str, char char62 = '\x2b', char char63 = '\x2f');

// RFC 4880 sec 6.4
std::string radix642ascii(std::string str, char char62 = '\x2b', char char63 = '\x2f');

// RFC 4880 sec 6.1
uint32_t crc24(const std::string & str);
#endif
