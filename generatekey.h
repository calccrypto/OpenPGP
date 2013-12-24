#include <ctime>

#include "PKA/DSA.h"
#include "PKA/ElGamal.h"
#include "PKA/RSA.h"
#include "OpenPGP.h"
#include "cfb.h"
#include "pgptime.h"
#include "PKCS1.h"
#include "signverify.h"
#include "usehash.h"

#ifndef __GENERATE_KEY__
#define __GENERATE_KEY__

void generate_keys(std::string & pub, std::string & pri, const std::string & passphrase = "", const std::string & username = "", const std::string & comment = "", const std::string & email = "");

#endif
