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
std::vector <integer> RSA_keygen(const uint32_t & bits = 1024);

// Encrypt some data
integer RSA_encrypt(integer & data, const std::vector <integer> & key);
integer RSA_encrypt(std::string & data, const std::vector <integer> & key);

// Decrypt some data
std::string RSA_decrypt(integer & data, const std::vector <integer> & key);

// Sign some data
integer RSA_sign(std::string & hashed_data, const integer & d, const integer & n);

// Verify signature
bool RSA_verify(std::string & data, std::vector <integer> & signature, std::vector <integer> & key, const uint8_t & hash);
#endif
