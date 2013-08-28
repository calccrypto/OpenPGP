#include <ctime>
#include <iostream>

#include "consts.h"
#include "common/includes.h"
#include "RNG/RNG.h"
#include "usehash.h"

#ifndef __PKCS1__
#define __PKCS1__
// RFC 4880 13.1.1
std::string EME_PKCS1_ENCODE(const std::string & m, const unsigned int & k);

// RFC 4880 13.1.2
std::string EME_PKCS1_DECODE(const std::string & m);

// RFC 4880 13.1.3
std::string EMSA_PKCS1(uint8_t & h, const unsigned int & mL);
#endif
