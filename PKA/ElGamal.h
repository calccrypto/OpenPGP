#include <vector>

#include "../common/integer.h"
#include "../RNG/RNG.h"

#ifndef __ELGAMAL__
#define __ELGAMAL__
std::vector <integer> ElGamal_keygen(unsigned int bits = 1024);
std::vector <integer> ElGamal_encrypt(integer & data, const std::vector <integer> & pub);
std::vector <integer> ElGamal_encrypt(std::string & data, const std::vector <integer> & pub);
std::string ElGamal_decrypt(std::vector <integer> & c, std::vector <integer> & pub, integer pri);
#endif
