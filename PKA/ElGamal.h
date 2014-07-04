#ifndef __ELGAMAL__
#define __ELGAMAL__

#include <vector>

#include "../mpi.h"

#include "../common/includes.h"
#include "../RNG/RNG.h"
#include "../pgptime.h"

std::vector <PGPMPI> ElGamal_keygen(unsigned int bits = 2048);
std::vector <PGPMPI> ElGamal_encrypt(const PGPMPI & data, const std::vector <PGPMPI> & pub);
std::vector <PGPMPI> ElGamal_encrypt(const std::string & data, const std::vector <PGPMPI> & pub);
std::string ElGamal_decrypt(std::vector <PGPMPI> & c, const std::vector <PGPMPI> & pri, const std::vector <PGPMPI> & pub);
#endif
