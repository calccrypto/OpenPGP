/*
verify.c
Functions to verify data signed by a PGP key

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

#ifndef __VERIFY__
#define __VERIFY__

#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

#include "Packets/packets.h"
#include "PKA/PKA.h"
#include "mpi.h"
#include "PGPKey.h"
#include "PGPCleartextSignature.h"
#include "PGPDetachedSignature.h"
#include "sigcalc.h"

// Internal functions
std::string find_keyid(const Tag2::Ptr & tag2);
std::vector <PGPMPI> find_matching_pub_key(const std::string & keyid, const PGPPublicKey & key);

bool pka_verify(const std::string & hashed_message, const uint8_t pka, const std::vector<PGPMPI> &key, const std::vector<PGPMPI> &signature, const uint8_t h = 0);
bool pka_verify(const std::string & hashed_message, const Tag2::Ptr & tag2, const std::vector <PGPMPI> & key, const uint8_t h = 0);
// /////////////////

bool verify_file(const PGPPublicKey & pub, const std::string & data, const PGPDetachedSignature & sig);
bool verify_file(const PGPSecretKey & pri, const std::string & data, const PGPDetachedSignature & sig);
bool verify_file(const PGPPublicKey & pub, std::ifstream & f, const PGPDetachedSignature & sig);
bool verify_file(const PGPSecretKey & pri, std::ifstream & f, const PGPDetachedSignature & sig);

// verify cleartext signature
bool verify_cleartext_signature(const PGPPublicKey & pub, const PGPCleartextSignature & message);
bool verify_cleartext_signature(const PGPSecretKey & pri, const PGPCleartextSignature & message);

// verify signature on key
bool verify_signature(const PGPPublicKey & pub, const PGPPublicKey & sig);
bool verify_signature(const PGPSecretKey & pri, const PGPPublicKey & sig);

// verifiy revocation certificate
bool verify_revoke(const Tag6::Ptr & pub, const Tag2::Ptr & rev);
bool verify_revoke(const PGPPublicKey & pub, const PGPPublicKey & rev);
bool verify_revoke(const PGPSecretKey & pri, const PGPPublicKey & rev);
#endif
