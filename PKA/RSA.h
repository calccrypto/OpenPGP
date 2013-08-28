#include <algorithm>
#include <vector>
#include <iostream>

#include "../consts.h"
#include "../common/includes.h"
#include "../common/integer.h"
#include "../RNG/RNG.h"
#include "../usehash.h"

#ifndef __RSA__
#define __RSA__

// Generate RSA key values
std::vector <integer> RSA_keygen(uint32_t bits = 1024);

// Encrypt some data
integer RSA_encrypt(std::string data, integer e, integer n);

// Decrypt some data
std::string RSA_decrypt(integer data, integer d, integer n);

// Sign some data
integer RSA_sign(std::string hashed_data, integer d, integer n);

// Verify signature
bool RSA_verify(std::string & data, std::vector <integer> & signature, std::vector <integer> & key, uint8_t hash);
#endif
