#include <vector>

#include <gmpxx.h>

#include "../common/includes.h"
#include "../RNG/RNG.h"
#include "../pgptime.h"

#ifndef __ELGAMAL__
#define __ELGAMAL__
std::vector <mpz_class> ElGamal_keygen(unsigned int bits = 1024);
std::vector <mpz_class> ElGamal_encrypt(const mpz_class & data, const std::vector <mpz_class> & pub);
std::vector <mpz_class> ElGamal_encrypt(const std::string & data, const std::vector <mpz_class> & pub);
std::string ElGamal_decrypt(std::vector <mpz_class> & c, const std::vector <mpz_class> & pri, const std::vector <mpz_class> & pub);
#endif
