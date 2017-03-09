/*
sign.h
Functions to sign some data with a PGP key

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

#ifndef __SIGN__
#define __SIGN__

#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>

#include "common/includes.h"
#include "Compress/Compress.h"
#include "Hashes/Hashes.h"
#include "Packets/packets.h"
#include "PKA/PKAs.h"
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
PKA::Values pka_sign(const std::string & digest, const uint8_t pka, const PKA::Values & pub, const PKA::Values & pri, const uint8_t hash, std::string & error);
PKA::Values pka_sign(const std::string & digest, const uint8_t pka, const PKA::Values & pub, const PKA::Values & pri, const uint8_t hash);

// Generates a new signature packet without PKA values
Tag2::Ptr create_sig_packet(const uint8_t version, const uint8_t type, const uint8_t pka, const uint8_t hash, const std::string & keyid);
// //////////////////////////////////////

// commmon arguments for signing
struct SignArgs{
    PGPSecretKey pri;                       // private key
    std::string passphrase;                 // passphrase for a key on the private key
    std::string id;                         // Key ID or User string of key to be used
    uint8_t version;                        // 3 or 4
    uint8_t hash;                           // hash algorithm to use for signing

    SignArgs(const PGPSecretKey & key,
             const std::string & pass,
             const uint8_t ver = 4,
             const uint8_t ha = Hash::SHA1)
        : pri(key),
          passphrase(pass),
          version(ver),
          hash(ha)
    {}

    bool valid(std::string & error) const{
        if (!pri.meaningful(error)){
            error += "Error: Bad Private Key.\n";
            return false;
        }

        if (Hash::NAME.find(hash) == Hash::NAME.end()){
            error += "Error: Hash algorithm number " + std::to_string(hash) + " not found.\n";
            return false;
        }

        return true;
    }
};

// detached signatures (not a standalone signature)
PGPDetachedSignature sign_detached_signature(const SignArgs & args, const std::string & data, std::string & error);
PGPDetachedSignature sign_detached_signature(const SignArgs & args, const std::string & data);

// 0x00: Signature of a binary document.
// signed file is embedded into output
PGPMessage sign_binary(const SignArgs & args, const std::string & filename, const std::string & data, const uint8_t compress, std::string & error);
PGPMessage sign_binary(const SignArgs & args, const std::string & filename, const std::string & data, const uint8_t compress);

// 0x01: Signature of a canonical text document.
PGPCleartextSignature sign_cleartext_signature(const SignArgs & args, const std::string & text, std::string & error);
PGPCleartextSignature sign_cleartext_signature(const SignArgs & args, const std::string & text);

// 0x02: Standalone signature.
// TODO Make this work
PGPDetachedSignature sign_standalone_signature(const SignArgs & args, const Tag2::Ptr & src, const uint8_t compress, std::string & error);
PGPDetachedSignature sign_standalone_signature(const SignArgs & args, const Tag2::Ptr & src, const uint8_t compress);

// 0x10: Generic certification of a User ID and Public-Key packet.
// 0x11: Persona certification of a User ID and Public-Key packet.
// 0x12: Casual certification of a User ID and Public-Key packet.
// 0x13: Positive certification of a User ID and Public-Key packet.
PGPPublicKey sign_primary_key(const SignArgs & args, const std::string & user, const PGPPublicKey & signee, const uint8_t cert, std::string & error);
PGPPublicKey sign_primary_key(const SignArgs & args, const std::string & user, const PGPPublicKey & signee, const uint8_t cert);

// 0x18: Subkey Binding Signature
Tag2::Ptr sign_subkey(const Tag5::Ptr & primary, const Tag7::Ptr & sub, const std::string & passphrase, const uint8_t hash = Hash::SHA1, const uint8_t version = 4);

// 0x19: Primary Key Binding Signature
Tag2::Ptr sign_primary_key_binding(const SignArgs & args, const PGPPublicKey & signee, std::string & error);
Tag2::Ptr sign_primary_key_binding(const SignArgs & args, const PGPPublicKey & signee);

// 0x1F: Signature directly on a key

// Found in revoke.h ///////////////////////
// 0x20: Key revocation signature
// 0x28: Subkey revocation signature
// 0x30: Certification revocation signature
// /////////////////////////////////////////

// 0x40: Timestamp signature.
// 0x50: Third-Party Confirmation signature.
#endif
