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

#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "common/includes.h"
#include "Compress/Compress.h"
#include "Packets/packets.h"
#include "PKA/PKA.h"
#include "decrypt.h"
#include "mpi.h"
#include "PGPCleartextSignature.h"
#include "PGPDetachedSignature.h"
#include "PGPKey.h"
#include "PGPMessage.h"
#include "pgptime.h"
#include "revoke.h"
#include "sigcalc.h"

// internal functions
// possibly returns wrong ID when multiple ID packets are present
ID::Ptr find_user_id(const PGPSecretKey & k);

std::vector <PGPMPI> pka_sign(const std::string & digest, const uint8_t pka, const std::vector <PGPMPI> & pub, const std::vector <PGPMPI> & pri, const uint8_t hash = 2);
std::vector <PGPMPI> pka_sign(const std::string & digest, const Tag5::Ptr & tag5, const std::string & passphrase, const uint8_t hash = 2);

// Generates new default signature packet
Tag2::Ptr create_sig_packet(const uint8_t type, const Tag5::Ptr & tag5, const ID::Ptr & id = nullptr, const uint8_t hash = 2);
Tag2::Ptr create_sig_packet(const uint8_t type, const PGPSecretKey & pri, const uint8_t hash = 2);
// //////////////////////////////////////

// Creates signatures
// common code for signing files
Tag2::Ptr sign_00(const PGPSecretKey & pri, const std::string & passphrase, const std::string & data, const uint8_t hash);
// 0x00: Signature of a binary document.
PGPDetachedSignature sign_detach(const PGPSecretKey & pri, const std::string & passphrase, const std::string & data, const uint8_t hash = 2);
PGPDetachedSignature sign_detach(const PGPSecretKey & pri, const std::string & passphrase, std::ifstream & f, const uint8_t hash = 2);
// Includes signed file
PGPMessage sign_message(const PGPSecretKey & pri, const std::string & passphrase, const std::string & filename, const std::string & data, const uint8_t hash = 2, const uint8_t compress = 2);
PGPMessage sign_message(const PGPSecretKey & pri, const std::string & passphrase, const std::string & filename, const uint8_t hash = 2, const uint8_t compress = 2);
PGPMessage sign_message(const PGPSecretKey & pri, const std::string & passphrase, const std::string & filename, std::ifstream & f, const uint8_t hash = 2, const uint8_t compress = 2);

// 0x01: Signature of a canonical text document.
PGPCleartextSignature sign_cleartext(const PGPSecretKey & pri, const std::string & passphrase, const std::string & text, const uint8_t hash = 2);

// 0x02: Standalone signature.
Tag2::Ptr standalone_signature(const Tag5::Ptr & key, const Tag2::Ptr & src, const std::string & passphrase, const uint8_t hash = 2);

// 0x10: Generic certification of a User ID and Public-Key packet.
// 0x11: Persona certification of a User ID and Public-Key packet.
// 0x12: Casual certification of a User ID and Public-Key packet.
// 0x13: Positive certification of a User ID and Public-Key packet.
// mainly used for key generation
Tag2::Ptr sign_primary_key(const Tag5::Ptr & key, const ID::Ptr & id, const std::string & passphrase, const uint8_t cert = 0x13, const uint8_t hash = 2);
// sign someone else's key; can be used for key generation
PGPPublicKey sign_primary_key(const PGPSecretKey & signer, const std::string & passphrase, const PGPPublicKey & signee, const uint8_t cert = 0x13, const uint8_t hash = 2);

// 0x18: Subkey Binding Signature
// mainly used for key generation
Tag2::Ptr sign_subkey(const Tag5::Ptr & primary, const Tag7::Ptr & sub, const std::string & passphrase, const uint8_t hash = 2);

// 0x19: Primary Key Binding Signature
Tag2::Ptr sign_primary_key_binding(const Tag7::Ptr & subpri, const std::string & passphrase, const Tag6::Ptr & primary, const Tag14::Ptr & subkey, const uint8_t hash = 2);
Tag2::Ptr sign_primary_key_binding(const PGPSecretKey & pri, const std::string & passphrase, const PGPPublicKey & signee, const uint8_t hash = 2);

// 0x1F: Signature directly on a key

// Found in revoke.h ///////////////////////
// 0x20: Key revocation signature
// 0x28: Subkey revocation signature
// 0x30: Certification revocation signature
// /////////////////////////////////////////

// 0x40: Timestamp signature.
// 0x50: Third-Party Confirmation signature.
#endif
