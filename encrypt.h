#include "PKA/ElGamal.h"
#include "PKA/RSA.h"
#include "cfb.h"
#include "OpenPGP.h"
#include "PKCS1.h"
#include "usehash.h"

#ifndef __PGPENCRYPT__
#define __PGPENCRYPT__
// Encrypt data
std::string encrypt(const std::string & data, PGP & pub, bool hash = true, uint8_t sym_alg = 9);
#endif
