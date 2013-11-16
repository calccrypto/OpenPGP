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
integer RSA_encrypt(integer & data, const std::vector <integer> & pub);
integer RSA_encrypt(std::string & data, const std::vector <integer> & pub);

// Decrypt some data
integer RSA_decrypt(integer & data, const std::vector <integer> & pri);

// Sign some data
integer RSA_sign(std::string & data, const std::vector <integer> & pri);
integer RSA_sign(integer & data, const std::vector <integer> & pri);

// Verify signature
bool RSA_verify(std::string & data, std::vector <integer> & signature, std::vector <integer> & pub, const uint8_t & hash);
#endif
