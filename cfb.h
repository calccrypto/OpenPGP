/*
cfn.h
OpenPGP CFB mode - RFC 4880 sec 13.9

Copyright (c) 2013 Jason Lee

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#ifndef __OPENPGP_CFB__
#define __OPENPGP_CFB__

#include <iostream>
#include <stdexcept>

#include "Encryptions/Encryptions.h"
#include "RNG/RNG.h"
#include "consts.h"

const std::string TDES_mode1 = "e";
const std::string TDES_mode2 = "d";
const std::string TDES_mode3 = "e";

SymAlg::Ptr use_sym_alg(const uint8_t sym_alg, const std::string & key, const std::string & key2 = "", const std::string & key3 = "");

// OpenPGP CFB as described in RFC 4880 section 13.9
std::string OpenPGP_CFB_encrypt(SymAlg::Ptr & crypt, const uint8_t packet, const std::string & data, std::string prefix = "");
std::string OpenPGP_CFB_decrypt(SymAlg::Ptr & crypt, const uint8_t packet, const std::string & data);
// Helper functions
std::string use_OpenPGP_CFB_encrypt(const uint8_t sym_alg, const uint8_t packet, const std::string & data, const std::string & key, const std::string & prefix = "", const std::string & key2 = "", const std::string & key3 = "");
std::string use_OpenPGP_CFB_decrypt(const uint8_t sym_alg, const uint8_t packet, const std::string & data, const std::string & key, const std::string & key2 = "", const std::string & key3 = "");

// Standard CFB mode
std::string normal_CFB_encrypt(SymAlg::Ptr & crypt, const std::string & data, std::string & IV);
std::string normal_CFB_decrypt(SymAlg::Ptr & crypt, const std::string & data, std::string & IV);
// Helper functions
std::string use_normal_CFB_encrypt(const uint8_t sym_alg, std::string data, std::string key, std::string IV, std::string key2 = "", std::string key3 = "");
std::string use_normal_CFB_decrypt(const uint8_t sym_alg, std::string data, std::string key, std::string IV, std::string key2 = "", std::string key3 = "");
#endif
