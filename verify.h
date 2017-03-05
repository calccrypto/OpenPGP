/*
verify.c
Functions to verify data signed by a PGP key

Copyright (c) 2013 - 2017 Jason Lee @ calccrypto at gmail.com

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

#include <iostream>
#include <list>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "Packets/packets.h"
#include "PKA/PKAs.h"
#include "mpi.h"
#include "PGPKey.h"
#include "PGPCleartextSignature.h"
#include "PGPDetachedSignature.h"
#include "PGPMessage.h"
#include "PKCS1.h"
#include "sigcalc.h"

// pka_verify with variables only
bool pka_verify(const std::string & digest, const uint8_t hash, const uint8_t pka, const PKA::Values & signing, const PKA::Values & signature);

// pka_verify with packets
bool pka_verify(const std::string & digest, const Tag6::Ptr signing, const Tag2::Ptr & signature);
// /////////////////

// detached signatures (not a standalone signature)
bool verify_detachedsig(const PGPPublicKey & pub, const std::string & data,    const PGPDetachedSignature & sig, std::string * error = nullptr);
bool verify_detachedsig(const PGPSecretKey & pri, const std::string & data,    const PGPDetachedSignature & sig, std::string * error = nullptr);
bool verify_detachedsig(const PGPPublicKey & pub,       std::istream & stream, const PGPDetachedSignature & sig, std::string * error = nullptr);
bool verify_detachedsig(const PGPSecretKey & pri,       std::istream & stream, const PGPDetachedSignature & sig, std::string * error = nullptr);

// 0x00: Signature of a binary document.
bool verify_message(const Tag6::Ptr & signing_key, const PGPMessage & m);   // called by the other verify_message functions
bool verify_message(const PGPPublicKey & pub,      const PGPMessage & m, std::string * error = nullptr);
bool verify_message(const PGPSecretKey & pri,      const PGPMessage & m, std::string * error = nullptr);

// 0x01: Signature of a canonical text document.
bool verify_cleartext_signature(const PGPPublicKey & pub, const PGPCleartextSignature & message, std::string * error = nullptr);
bool verify_cleartext_signature(const PGPSecretKey & pri, const PGPCleartextSignature & message, std::string * error = nullptr);

// 0x02: Standalone signature.

// 0x10: Generic certification of a User ID and Public-Key packet.
// 0x11: Persona certification of a User ID and Public-Key packet.
// 0x12: Casual certification of a User ID and Public-Key packet.
// 0x13: Positive certification of a User ID and Public-Key packet.
bool verify_key(const PGPPublicKey & pub, const PGPPublicKey & sig, std::string * error = nullptr);
bool verify_key(const PGPSecretKey & pri, const PGPPublicKey & sig, std::string * error = nullptr);

// 0x18: Subkey Binding Signature

// 0x19: Primary Key Binding Signature

// 0x1F: Signature directly on a key

// 0x20: Key revocation signature
// 0x28: Subkey revocation signature
// 0x30: Certification revocation signature
bool verify_revoke(const Tag6::Ptr & pub, const Tag2::Ptr & rev);           // called by the other verify_revoke functions
bool verify_revoke(const PGPPublicKey & pub, const PGPPublicKey & rev, std::string * error = nullptr);
bool verify_revoke(const PGPSecretKey & pri, const PGPPublicKey & rev, std::string * error = nullptr);

// 0x40: Timestamp signature.

// 0x50: Third-Party Confirmation signature.

#endif
