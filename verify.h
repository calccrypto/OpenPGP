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

#include <list>
#include <sstream>
#include <stdexcept>
#include <string>

#include "PGPCleartextSignature.h"
#include "PGPDetachedSignature.h"
#include "PGPKey.h"
#include "PGPMessage.h"
#include "PGPRevocationCertificate.h"
#include "PKA/PKAs.h"
#include "PKCS1.h"
#include "Packets/packets.h"
#include "mpi.h"
#include "sigcalc.h"

// pka_verify with variables only
int pka_verify(const std::string & digest, const uint8_t hash, const uint8_t pka, const PKA::Values & signer, const PKA::Values & signee, std::string & error);

// pka_verify with packets
int pka_verify(const std::string & digest, const Key::Ptr & signer, const Tag2::Ptr & signee, std::string & error);
// /////////////////

// detached signatures (not a standalone signature)
int verify_detached_signature(const PGPKey & key, const std::string & data, const PGPDetachedSignature & sig, std::string & error);
int verify_detached_signature(const PGPKey & key, const std::string & data, const PGPDetachedSignature & sig);

// 0x00: Signature of a binary document.
int verify_message(const PGPKey & key, const PGPMessage & message, std::string & error);
int verify_message(const PGPKey & key, const PGPMessage & message);

// 0x01: Signature of a canonical text document.
int verify_cleartext_signature(const PGPKey & pub, const PGPCleartextSignature & message, std::string & error);
int verify_cleartext_signature(const PGPKey & pub, const PGPCleartextSignature & message);

// 0x02: Standalone signature.

// 0x10: Generic certification of a User ID and Public-Key packet.
// 0x11: Persona certification of a User ID and Public-Key packet.
// 0x12: Casual certification of a User ID and Public-Key packet.
// 0x13: Positive certification of a User ID and Public-Key packet.
int verify_key(const Key::Ptr & signer_key, const Key::Ptr & signee_key, const User::Ptr & signee_id, const Tag2::Ptr & signee_signature, std::string & error);
int verify_key(const PGPKey & signer, const PGPKey & signee, std::string & error);
int verify_key(const PGPKey & signer, const PGPKey & signee);

// 0x18: Subkey Binding Signature

// 0x19: Primary Key Binding Signature

// 0x1F: Signature directly on a key

// 0x20: Key revocation signature
// 0x28: Subkey revocation signature
// 0x30: Certification revocation signature
int verify_revoke(const PGPKey & key, const PGPRevocationCertificate & revoke, std::string & error);
int verify_revoke(const PGPKey & key, const PGPRevocationCertificate & revoke);

// 0x40: Timestamp signature.

// 0x50: Third-Party Confirmation signature.

#endif
