#include "PKA/ElGamal.h"
#include "PKA/RSA.h"
#include "cfb.h"
#include "consts.h"
#include "OpenPGP.h"
#include "packets.h"
#include "PKCS1.h"
#include "s2k.h"
#include "usehash.h"

#ifndef __DECRYPT__
#define __DECRYPT__
std::string pka_decrypt(uint8_t pka, std::vector <integer> data, std::vector <integer> key, integer pri);
std::vector <integer> decrypt_secret_key(Tag5 * pri, std::string pass);
std::string decrypt_message(PGP & m, PGP & pri, std::string pass);
#endif
