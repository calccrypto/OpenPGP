/*
Public Key Algorithm list
*/

#ifndef __PKA__
#define __PKA__

#include <sstream>

#include <gmpxx.h>

#include "DSA.h"
#include "ElGamal.h"
#include "RSA.h"

/*
param:
    DSA = {L, N}
    ElGamal = {bits}
    RSA = {bits}

pub and pri are destination containers
*/
void generate_key_pair(const uint8_t pka, const std::vector <unsigned int> & param, std::vector <mpz_class> & pub, std::vector <mpz_class> & pri);

#endif
