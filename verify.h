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
#include <list>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "Packets/packets.h"
#include "PKA/PKA.h"
#include "mpi.h"
#include "PGPKey.h"
#include "PGPCleartextSignature.h"
#include "PGPDetachedSignature.h"
#include "PGPMessage.h"
#include "PKCS1.h"
#include "sigcalc.h"

// pka_verify with variables only
bool pka_verify(const std::string & digest, const uint8_t hash, const uint8_t pka, const std::vector <PGPMPI> & signing, const std::vector <PGPMPI> & signature);
// pka_verify with packets
bool pka_verify(const std::string & digest, const Tag6::Ptr signing, const Tag2::Ptr & signature);
// /////////////////

// verify cleartext signature
bool verify_cleartext_signature(const PGPPublicKey & pub, const PGPCleartextSignature & message);
bool verify_cleartext_signature(const PGPSecretKey & pri, const PGPCleartextSignature & message);

// verify detached signatures
bool verify_detachedsig(const PGPPublicKey & pub, const std::string & data, const PGPDetachedSignature & sig);
bool verify_detachedsig(const PGPSecretKey & pri, const std::string & data, const PGPDetachedSignature & sig);
bool verify_detachedsig(const PGPPublicKey & pub, std::ifstream & f, const PGPDetachedSignature & sig);
bool verify_detachedsig(const PGPSecretKey & pri, std::ifstream & f, const PGPDetachedSignature & sig);

// verify OpenPGP Messages: signed, encrypted, or compressed files
bool verify_message(const Tag6::Ptr & signing_key, const PGPMessage & m); // called by the other verify_message functions
bool verify_message(const PGPPublicKey & pub, const PGPMessage & m);
bool verify_message(const PGPSecretKey & pri, const PGPMessage & m);

// verify signature on key
bool verify_key(const PGPPublicKey & pub, const PGPPublicKey & sig);
bool verify_key(const PGPSecretKey & pri, const PGPPublicKey & sig);

// verify revocation certificate
bool verify_revoke(const Tag6::Ptr & pub, const Tag2::Ptr & rev);
bool verify_revoke(const PGPPublicKey & pub, const PGPPublicKey & rev);
bool verify_revoke(const PGPSecretKey & pri, const PGPPublicKey & rev);
#endif
