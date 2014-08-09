/*
sign.h
Functions to sign some data with a PGP key

Copyright (c) 2013, 2014 Jason Lee

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

#ifndef __SIGN__
#define __SIGN__

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "common/includes.h"
#include "Packets/packets.h"
#include "PKA/PKA.h"
#include "decrypt.h"
#include "mpi.h"
#include "PGPCleartextSignature.h"
#include "PGPDetachedSignature.h" // not used yet
#include "PGPKey.h"
#include "PGPMessage.h"
#include "pgptime.h"
#include "revoke.h"
#include "sigcalc.h"

// internal functions
// Extract private key data
Tag5::Ptr find_signing_key(const PGPSecretKey & k);
ID::Ptr find_signer_id(const PGPSecretKey & k);

std::vector <PGPMPI> pka_sign(std::string hashed_data, const uint8_t pka, const std::vector <PGPMPI> & pub, const std::vector <PGPMPI> & pri, const uint8_t h = 0);
std::vector <PGPMPI> pka_sign(const std::string & hashed_data, const Tag5::Ptr & tag5, const std::string & passphrase, const uint8_t h = 0);

// Generates new default signature packet
Tag2::Ptr create_sig_packet(const uint8_t type, const Tag5::Ptr & tag5, const ID::Ptr & id = ID::Ptr());
Tag2::Ptr create_sig_packet(const uint8_t type, const PGPSecretKey & pri);
// /////////////////


// Creates signatures
// 0x00
PGPMessage sign_file(const PGPSecretKey & pri, const std::string & passphrase, const std::string & data);
PGPMessage sign_file(const PGPSecretKey & pri, const std::string & passphrase, std::ifstream & f);

// 0x01
PGPCleartextSignature sign_cleartext(const PGPSecretKey & pri, const std::string & passphrase, const std::string & text);

// 0x02
Tag2::Ptr standalone_signature(const Tag2::Ptr & src, const std::string & passphrase, const Tag5::Ptr & key);

// 0x10 - 13
// mainly used for key generation
Tag2::Ptr sign_primary_key(const Tag5::Ptr & key, const ID::Ptr & id, const std::string & passphrase, const uint8_t cert = 0x13);
//signing someone else's key; can be used for key generation
PGPPublicKey sign_primary_key(const PGPSecretKey & signer, const std::string & passphrase, const PGPPublicKey & signee, const uint8_t cert = 0x13);

// 0x18 - 0x19
// mainly used for key generation
Tag2::Ptr sign_subkey(const Tag5::Ptr & primary, const Tag7::Ptr & sub, const std::string & passphrase, const uint8_t binding = 0x18);
// not sure if subkey signing is a thing

// 0x40

// 0x50
#endif
