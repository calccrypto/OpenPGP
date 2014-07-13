/*
Input data should already be formatted and ready for hashing
*/

#ifndef __DSA__
#define __DSA__

#include <vector>
#include <iostream>

#include "../mpi.h"

#include "../common/cryptomath.h"
#include "../common/includes.h"
#include "../RNG/RNG.h"
#include "../pgptime.h"

// Generate new set of parameters
std::vector <PGPMPI> new_DSA_public(const uint32_t & L = 2048, const uint32_t & N = 256);

// Generate new keypair with parameters
std::vector <PGPMPI> DSA_keygen(std::vector <PGPMPI> & pub);

// Sign hash of data
std::vector <PGPMPI> DSA_sign(const PGPMPI & data, const std::vector <PGPMPI> & pri, const std::vector <PGPMPI> & pub, PGPMPI k = 0);
std::vector <PGPMPI> DSA_sign(const std::string & data, const std::vector <PGPMPI> & pri, const std::vector <PGPMPI> & pub, PGPMPI k = 0);

// Verify signature on hash
bool DSA_verify(const PGPMPI & data, const std::vector <PGPMPI> & sig, const std::vector <PGPMPI> & pub);
bool DSA_verify(const std::string & data, const std::vector <PGPMPI> & sig, const std::vector <PGPMPI> & pub);
#endif
