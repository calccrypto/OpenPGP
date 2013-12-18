#include "PKA/DSA.h"
#include "PKA/RSA.h"
#include "OpenPGP.h"
#include "signverify.h"

#ifndef __VERIFY__
#define __VERIFY__

std::string find_keyid(Tag2 * tag2);
std::vector <mpz_class> find_matching_pub_key(std::string keyid, PGP & key);

bool pka_verify(std::string & hashed_message, Tag2 * tag2, std::vector <mpz_class> & key);

// Use string.size() to check if input was verified.
bool verify_file(std::string filename, PGP & sig, PGP & key);
bool verify_file(std::ifstream & f, PGP & sig, PGP & key);

bool verify_message(PGPMessage & message, PGP & key);
bool verify_signature(PGP & sig, PGP & key);
bool verify_revoke(PGP & key, PGP & rev);
#endif
