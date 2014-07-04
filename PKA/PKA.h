/*
Public Key Algorithm list
*/

#ifndef __PKA__
#define __PKA__

#include <sstream>

#include "../mpi.h"

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
void generate_key_pair(const uint8_t pka, const std::vector <unsigned int> & param, std::vector <PGPMPI> & pub, std::vector <PGPMPI> & pri);

#endif
