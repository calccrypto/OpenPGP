#include <iostream>
#include <vector>

#include "common/includes.h"
#include "PKA/DSA.h"
#include "PKA/RSA.h"
#include "decrypt.h"
#include "packets.h"
#include "pgptime.h"

#ifndef __SIGN__
#define __SIGN__
// Extract private key data
Tag5 * find_signing_packet(PGP & k);
Tag13 * find_signer_id(PGP & k);

std::vector <integer> pka_sign(std::string hashed_message, uint8_t pka, std::vector <integer> & pub, std::vector <integer> & pri);

// Will generate new default Signature packet if none is given.
// Only signs data. Output is essentially a detached signature.
Tag2 * sign(uint8_t type, std::string hashed_data, Tag5 * tag5, std::string pass, Tag2 * tag2 = NULL);
#endif
