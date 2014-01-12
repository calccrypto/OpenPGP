#ifndef __RSA__
#define __RSA__

#include <algorithm>
#include <vector>
#include <iostream>

#include <gmpxx.h>

#include "../consts.h"
#include "../common/includes.h"
#include "../RNG/RNG.h"
#include "../pgptime.h"

// Generate RSA key values
std::vector <mpz_class> RSA_keygen(const uint32_t & bits = 2048);

// Encrypt some data
mpz_class RSA_encrypt(mpz_class & data, const std::vector <mpz_class> & pub);
mpz_class RSA_encrypt(const std::string & data, const std::vector <mpz_class> & pub);

// Decrypt some data
mpz_class RSA_decrypt(mpz_class & data, const std::vector <mpz_class> & pri, const std::vector <mpz_class> & pub);

// Sign some data
mpz_class RSA_sign(mpz_class & data, const std::vector <mpz_class> & pri, const std::vector <mpz_class> & pub);
mpz_class RSA_sign(const std::string & data, const std::vector <mpz_class> & pri, const std::vector <mpz_class> & pub);

// Verify signature
bool RSA_verify(mpz_class & data, const std::vector <mpz_class> & signature, const std::vector <mpz_class> & pub);
bool RSA_verify(const std::string & data, const std::vector <mpz_class> & signature, const std::vector <mpz_class> & pub);
#endif
