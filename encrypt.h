/*
encrypt.h
Function to encrypt data with a PGP public key

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

#ifndef __PGPENCRYPT__
#define __PGPENCRYPT__

#include <stdexcept>
#include <string>

#include "Compress/Compress.h"
#include "Encryptions/Encryptions.h"
#include "Hashes/Hashes.h"
#include "PGPKey.h"
#include "PGPMessage.h"
#include "PKA/PKAs.h"
#include "PKCS1.h"
#include "cfb.h"
#include "revoke.h"
#include "sign.h"

struct EncryptArgs{
    std::string filename;
    std::string data;
    uint8_t sym;                    // symmetric key algorithm used to encrypt data
    uint8_t comp;                   // compression algorithm for encrypted data
    bool mdc;
    PGPSecretKey::Ptr signer;       // for signing data
    std::string passphrase;         // only used when signer is present
    uint8_t hash;                   // hash used to sign data

    EncryptArgs(const std::string & fname = "",
                const std::string & dat = "",
                const uint8_t sym_alg = Sym::AES256,
                const uint8_t comp_alg = Compression::ZLIB,
                const bool mod_detect = true,
                const PGPSecretKey::Ptr & signing_key = nullptr,
                const std::string & pass = "",
                const uint8_t hash_alg = Hash::SHA1)
        : filename(fname),
          data(dat),
          sym(sym_alg),
          comp(comp_alg),
          mdc(mod_detect),
          signer(signing_key),
          passphrase(pass),
          hash(hash_alg)
    {}

    bool valid(std::string & error) const{
        if (Sym::NAME.find(sym) == Sym::NAME.end()){
            error += "Error: Bad Symmetric Key Algorithm: " + std::to_string(sym);
            return false;
        }

        if (Compression::NAME.find(comp) == Compression::NAME.end()){
            error += "Error: Bad Compression Algorithm: " + std::to_string(comp);
            return false;
        }

        if (Hash::NAME.find(hash) == Hash::NAME.end()){
            error += "Error: Bad Hash Algorithm: " + std::to_string(hash);
            return false;
        }

        return true;
    }
};

// encrypt data once session key has been generated
Packet::Ptr encrypt_data(const EncryptArgs & args,
                         const std::string & session_key,
                         std::string & error);

// encrypt with public key
PGPMessage encrypt_pka(const EncryptArgs & args,
                       const PGPPublicKey & pub,
                       std::string & error);

// encrypt with passphrase
PGPMessage encrypt_sym(const EncryptArgs & args,
                       const std::string & passphrase,
                       const uint8_t key_hash,
                       std::string & error);

#endif
