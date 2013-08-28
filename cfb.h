/*
OpenPGP CFB mode
RFC 4880 sec 13.9
*/

#include "Encryptions/Encryptions.h"
#include "RNG/RNG.h"
#include "consts.h"

#ifndef __OPENPGP_OpenPGP_CFB__
#define __OPENPGP_OpenPGP_CFB__

const std::string TDES_mode1 = "e";
const std::string TDES_mode2 = "d";
const std::string TDES_mode3 = "e";

std::string xor_strings(std::string str1, std::string str2);

// OpenPGP CFB as described in RFC 4880 section 13.9
std::string OpenPGP_CFB_encrypt(SymAlg * crypt, uint8_t packet, std::string data, std::string prefix = "");
std::string OpenPGP_CFB_decrypt(SymAlg * crypt, uint8_t packet, std::string data);
// Helper functions
std::string use_OpenPGP_CFB_encrypt(uint8_t sym_alg, uint8_t packet, std::string data, std::string key, std::string prefix = "", std::string key2 = "", std::string key3 = "");
std::string use_OpenPGP_CFB_decrypt(uint8_t sym_alg, uint8_t packet, std::string data, std::string key, std::string key2 = "", std::string key3 = "");

// Standard CFB mode
std::string normal_CFB_encrypt(SymAlg * crypt, std::string data, std::string IV);
std::string normal_CFB_decrypt(SymAlg * crypt, std::string data, std::string IV);
// Helper functions
std::string use_normal_CFB_encrypt(uint8_t sym_alg, std::string data, std::string key, std::string IV, std::string key2 = "", std::string key3 = "");
std::string use_normal_CFB_decrypt(uint8_t sym_alg, std::string data, std::string key, std::string IV, std::string key2 = "", std::string key3 = "");
#endif
