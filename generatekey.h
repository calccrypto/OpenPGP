/*
generatekey.h
Key pair generation function

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

#ifndef __GENERATE_KEY__
#define __GENERATE_KEY__

#include <string>
#include <vector>

#include "Hashes/Hashes.h"
#include "PGPKey.h"
#include "PKA/PKAs.h"
#include "PKCS1.h"
#include "cfb.h"
#include "mpi.h"
#include "pgptime.h"
#include "sigcalc.h"
#include "sign.h"

// self-signs all signature packets whose Key ID is the given key's Key ID
// not doing revocations for now
bool fill_key_sigs(PGPSecretKey & private_key, const std::string & passphrase, std::string & error);

struct KeyGen{
    std::string passphrase;

    // Primary Key
    uint8_t     pka         = PKA::RSA_ENCRYPT_OR_SIGN;
    std::size_t bits        = 2048;
    uint8_t     sym         = Sym::AES256;          // symmetric key algorithm used by S2K
    uint8_t     hash        = Hash::SHA256;         // hash algorithm used by S2K

    // User ID (s)
    struct UserID{
        std::string user    = "";
        std::string comment = "";
        std::string email   = "";
        uint8_t     sig     = Hash::SHA256;         // hash algorithm used to sign
        time_t      expire  = 0;
    };

    // at least 1 User ID packet
    std::vector <UserID> uids;

    // Subkey(s)
    struct SubkeyGen{
        uint8_t     pka     = PKA::RSA_ENCRYPT_OR_SIGN;
        std::size_t bits    = 2048;
        uint8_t     sym     = Sym::AES256;          // symmetric key algorithm used by S2K
        uint8_t     hash    = Hash::SHA256;         // hash algorithm used by S2K
        uint8_t     sig     = Hash::SHA256;         // hash algorithm used to sign
        time_t      expire  = 0;
    };

    // 0 or more subkeys
    std::vector <SubkeyGen> subkeys;

    bool valid(std::string & error) const{
        if (PKA::NAME.find(pka) == PKA::NAME.end()){
            error += "Error: Bad Public Key Algorithm: " + std::to_string(pka);
            return false;
        }

        if (!(PKA::can_sign(pka))){
            error += "Error: Primary key should be able to sign.\n";
            return false;
        }

        if (bits < 512){
            error += "Error: Primary PKA key size should be at least 512 bits.\n";
            return false;
        }

        if (Sym::NAME.find(sym) == Sym::NAME.end()){
            error += "Error: Bad Symmetric Key Algorithm: " + std::to_string(sym);
            return false;
        }

        if (Hash::NAME.find(hash) == Hash::NAME.end()){
            error += "Error: Bad Hash Algorithm: " + std::to_string(hash);
            return false;
        }

        if (!uids.size()){
            error += "Error: Need at least 1 User ID.\n";
            return false;
        }

        for(UserID const & uid : uids){
            if (Hash::NAME.find(uid.sig) == Hash::NAME.end()){
                error += "Error: Bad Hash Algorithm: " + std::to_string(uid.sig);
                return false;
            }

            if ((pka == PKA::DSA) && (Hash::LENGTH.at(uid.sig) < 256)){
                error += "Error: DSA needs a 256 bit or larger hash.\n";
                return false;
            }
        }

        for(SubkeyGen const & subkey : subkeys){
            if (PKA::NAME.find(subkey.pka) == PKA::NAME.end()){
                error += "Error: Bad Public Key Algorithm: " + std::to_string(subkey.pka);
                return false;
            }

            if (subkey.bits < 512){
                error += "Error: Subkey PKA key size should be at least 512 bits.\n";
                return false;
            }

            if (Sym::NAME.find(subkey.sym) == Sym::NAME.end()){
                error += "Error: Bad Symmetric Key Algorithm: " + std::to_string(subkey.sym);
                return false;
            }

            if (Hash::NAME.find(subkey.hash) == Hash::NAME.end()){
                error += "Error: Bad Hash Algorithm: " + std::to_string(subkey.hash);
                return false;
            }

            if (Hash::NAME.find(subkey.sig) == Hash::NAME.end()){
                error += "Error: Bad Hash Algorithm: " + std::to_string(subkey.sig);
                return false;
            }

            if ((subkey.pka == PKA::DSA) && (Hash::LENGTH.at(subkey.sig) < 256)){
                error += "Error: DSA needs a 256 bit or larger hash.\n";
                return false;
            }
        }

        return true;
    }
};

// preset key generation
// return sin a private key
// public key can be extracted from the private key
PGPSecretKey generate_key(KeyGen & config, std::string & error);

#endif
