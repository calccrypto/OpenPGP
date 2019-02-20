/*
sign.h
Functions to sign some data with a PGP key

Copyright (c) 2013 - 2019 Jason Lee @ calccrypto at gmail.com

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

#include "CleartextSignature.h"
#include "Compress/Compress.h"
#include "DetachedSignature.h"
#include "Hashes/Hashes.h"
#include "Key.h"
#include "Message.h"
#include "Misc/mpi.h"
#include "Misc/pgptime.h"
#include "Misc/sigcalc.h"
#include "PKA/PKAs.h"
#include "Packets/Packets.h"
#include "common/includes.h"
#include "decrypt.h"
#include "revoke.h"
#include "verify.h"

namespace OpenPGP {
    namespace Sign {
        // internal functions
        PKA::Values with_pka(const std::string & digest, const uint8_t pka, const PKA::Values & pri, const PKA::Values & pub, const uint8_t hash);

        // Generates a new signature packet without PKA values
        Packet::Tag2::Ptr create_sig_packet(const uint8_t version, const uint8_t type, const uint8_t pka, const uint8_t hash, const std::string & keyid);
        // //////////////////////////////////////

        // commmon arguments for signing
        struct Args{
            SecretKey pri;                              // private key
            std::string passphrase;                     // passphrase for a key on the private key
            uint8_t version;                            // 3 or 4
            uint8_t hash;                               // hash algorithm to use for signing

            Args(const SecretKey & key,
                 const std::string & pass,
                 const uint8_t ver = 4,
                 const uint8_t ha = Hash::ID::SHA1)
                : pri(key),
                  passphrase(pass),
                  version(ver),
                  hash(ha)
                {}

            bool valid() const{
                if (!pri.meaningful()){
                    // "Error: Bad Private Key.\n";
                    return false;
                }

                if ((version != 3) && (version != 4)){
                    // "Error: Bad version: " + std::to_string(version) + "\n";
                    return false;
                }

                if (Hash::NAME.find(hash) == Hash::NAME.end()){
                    // "Error: Hash algorithm number " + std::to_string(hash) + " not found.\n";
                    return false;
                }

                return true;
            }
        };

        // detached signatures (not a standalone signature)
        DetachedSignature detached_signature(const Args & args, const std::string & data);

        // 0x00: Signature of a binary document.
        // signed file is embedded into output
        Message binary(const Args & args, const std::string & filename, const std::string & data, const uint8_t compress);

        // 0x01: Signature of a canonical text document.
        CleartextSignature cleartext_signature(const Args & args, const std::string & text);

        // 0x02: Standalone signature.

        // 0x10: Generic certification of a User ID and Public-Key packet.
        // 0x11: Persona certification of a User ID and Public-Key packet.
        // 0x12: Casual certification of a User ID and Public-Key packet.
        // 0x13: Positive certification of a User ID and Public-Key packet.
        Packet::Tag2::Ptr primary_key(const Packet::Tag5::Ptr signer_signing_key, const std::string & passphrase, const Packet::Key::Ptr & signee_primary_key, const Packet::User::Ptr & signee_id, Packet::Tag2::Ptr & sig);
        PublicKey primary_key(const Args & args, const PublicKey & signee, const std::string & user, const uint8_t cert);

        // 0x18: Subkey Binding Signature
        Packet::Tag2::Ptr subkey_binding(const Packet::Tag5::Ptr & primary, const std::string & passphrase, const Packet::Tag7::Ptr & sub, Packet::Tag2::Ptr & sig);

        // 0x19: Primary Key Binding Signature
        Packet::Tag2::Ptr primary_key_binding(const Args & args, const PublicKey & signee);

        // 0x1F: Signature directly on a key

        // Found in revoke.h ///////////////////////
        // 0x20: Key revocation signature
        // 0x28: Subkey revocation signature
        // 0x30: Certification revocation signature
        // /////////////////////////////////////////

        // 0x40: Timestamp signature.
        DetachedSignature timestamp(const Args & args, const uint32_t time);

        // 0x50: Third-Party Confirmation signature.
    }
}

#endif
