#ifndef __RSA__
#define __RSA__

#include <algorithm>
#include <vector>
#include <iostream>

#include "../mpi.h"

#include "../consts.h"
#include "../common/includes.h"
#include "../RNG/RNG.h"
#include "../pgptime.h"

// Generate RSA key values
std::vector <PGPMPI> RSA_keygen(const uint32_t & bits = 2048);

// Encrypt some data
PGPMPI RSA_encrypt(const PGPMPI & data, const std::vector <PGPMPI> & pub);
PGPMPI RSA_encrypt(const std::string & data, const std::vector <PGPMPI> & pub);

// Decrypt some data
PGPMPI RSA_decrypt(const PGPMPI & data, const std::vector <PGPMPI> & pri, const std::vector <PGPMPI> & pub);

// Sign some data
PGPMPI RSA_sign(const PGPMPI & data, const std::vector <PGPMPI> & pri, const std::vector <PGPMPI> & pub);
PGPMPI RSA_sign(const std::string & data, const std::vector <PGPMPI> & pri, const std::vector <PGPMPI> & pub);

// Verify signature
bool RSA_verify(const PGPMPI & data, const std::vector <PGPMPI> & signature, const std::vector <PGPMPI> & pub);
bool RSA_verify(const std::string & data, const std::vector <PGPMPI> & signature, const std::vector <PGPMPI> & pub);
#endif
