/*
Input data should already be formatted and ready for hashing
*/

#include <vector>
#include <iostream>

#include <gmpxx.h>

#include "../common/cryptomath.h"
#include "../Hashes/Hashes.h"
#include "../RNG/RNG.h"
#include "../usehash.h"

#ifndef __DSA__
#define __DSA__
//  {p, q, g, y}
std::vector <mpz_class> new_DSA_public(uint32_t L = 1024, uint32_t N = 160);
mpz_class DSA_keygen(std::vector <mpz_class> & pub);
std::vector <mpz_class> DSA_sign(std::string & data, const std::vector <mpz_class> & pri, const std::vector <mpz_class> & pub);
bool DSA_verify(std::string & data, const std::vector <mpz_class> & sig, const std::vector <mpz_class> & pub);
#endif
