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

#include "Encryptions/Encryptions.h"
#include "Hashes/Hashes.h"
#include "Key.h"
#include "Misc/PKCS1.h"
#include "Misc/cfb.h"
#include "Misc/mpi.h"
#include "Misc/pgptime.h"
#include "Misc/sigcalc.h"
#include "PKA/PKAs.h"
#include "sign.h"

namespace OpenPGP {

    // self-signs all signature packets whose Key ID is the given key's Key ID
    // not doing revocations for now
    bool fill_key_sigs(SecretKey & private_key, const std::string & passphrase);

    struct KeyGen{
        std::string passphrase;

        // Primary Key
        uint8_t     pka         = PKA::ID::RSA_ENCRYPT_OR_SIGN;
        std::size_t bits        = 2048;
        uint8_t     sym         = Sym::ID::AES256;          // symmetric key algorithm used by S2K
        uint8_t     hash        = Hash::ID::SHA256;         // hash algorithm used by S2K

        // User ID (s)
        struct UserID{
            std::string user    = "";
            std::string comment = "";
            std::string email   = "";
            uint8_t     sig     = Hash::ID::SHA256;         // hash algorithm used to sign
            uint32_t    expire  = 0;
        };

        // at least 1 User ID packet
        std::vector <UserID> uids;

        // Subkey(s)
        struct SubkeyGen{
            uint8_t     pka     = PKA::ID::RSA_ENCRYPT_OR_SIGN;
            std::size_t bits    = 2048;
            uint8_t     sym     = Sym::ID::AES256;          // symmetric key algorithm used by S2K
            uint8_t     hash    = Hash::ID::SHA256;         // hash algorithm used by S2K
            uint8_t     sig     = Hash::ID::SHA256;         // hash algorithm used to sign
            uint32_t    expire  = 0;
        };

        // 0 or more subkeys
        std::vector <SubkeyGen> subkeys;

        bool valid() const{
            if (PKA::NAME.find(pka) == PKA::NAME.end()){
                // "Error: Bad Public Key Algorithm: " + std::to_string(pka);
                return false;
            }

            if (!PKA::can_sign(pka)){
                // "Error: Primary key should be able to sign.\n";
                return false;
            }

            #ifdef GPG_COMPATIBLE
            if (PKA::is_RSA(pka)){
                if ((bits < 1024) || (bits > 4096)){
                    // "Error: RSA key size should be between 1024 and 4096 bits.\n";
                    return false;
                }

                if (bits % 32){
                    // "Error: GPG only accepts keys whose size is a multiple of 32.\n";
                    return false;
                }
            }
            else if (PKA::ID::DSA == pka){
                if ((bits < 1024) || (bits > 3072)){
                    // "Error: DSA key size should be between 1024 and 3072 bits.\n";
                    return false;
                }

                if (bits % 64){
                    // "Error: GPG only accepts DSA keys whose size is a multiple of 64.\n";
                    return false;
                }
            }
            else if (PKA::ID::ECDSA == pka || PKA::ID::EdDSA == pka){
                if ((bits < 160) || (bits > 1024)){ // [WARNING] THIS VALUE ARE NOT VERIFIED!!
                    // "Error: ECDSA/EdDSA key size should be between 160 and 1024 bits.\n";
                    return false;
                }
            }
            else{
                // "Error: Unknown PKA " + std::to_string(pka) + " got through filter.\n";
                return false;
            }
            #endif

            if (Sym::NAME.find(sym) == Sym::NAME.end()){
                // "Error: Bad Symmetric Key Algorithm: " + std::to_string(sym);
                return false;
            }

            if (Hash::NAME.find(hash) == Hash::NAME.end()){
                // "Error: Bad Hash Algorithm: " + std::to_string(hash);
                return false;
            }

            if (!uids.size()){
                // "Error: Need at least 1 User ID.\n";
                return false;
            }

            for(UserID const & uid : uids){
                if (Hash::NAME.find(uid.sig) == Hash::NAME.end()){
                    // "Error: Bad Hash Algorithm: " + std::to_string(uid.sig);
                    return false;
                }

                if ((pka == PKA::ID::DSA) && (Hash::LENGTH.at(uid.sig) < 256)){
                    // "Error: DSA needs a 256 bit or larger hash.\n";
                    return false;
                }
            }

            for(SubkeyGen const & subkey : subkeys){
                if (PKA::NAME.find(subkey.pka) == PKA::NAME.end()){
                    // "Error: Bad Public Key Algorithm: " + std::to_string(subkey.pka);
                    return false;
                }

                #ifdef GPG_COMPATIBLE
                if (PKA::is_RSA(subkey.pka)){
                    if ((subkey.bits < 1024) || (subkey.bits > 4096)){
                        // "Error: RSA key size should be between 1024 and 4096 bits.\n";
                        return false;
                    }

                    if (subkey.bits % 32){
                        // "Error: GPG only accepts keys whose size is a multiple of 32.\n";
                        return false;
                    }
                }
                else if ((PKA::ID::DSA == subkey.pka) || (PKA::ID::ELGAMAL == subkey.pka)){
                    if ((subkey.bits < 1024) || (subkey.bits > 3072)){
                        // "Error: DSA/ElGamal key size should be between 1024 and 3072 bits.\n";
                        return false;
                    }

                    if (subkey.bits % 64){
                        // "Error: GPG only accepts DSA/ElGamal keys whose size is a multiple of 64.\n";
                        return false;
                    }
                }
                else if (PKA::ID::ECDSA == subkey.pka || PKA::ID::EdDSA == subkey.pka || PKA::ID::ECDH == subkey.pka){
                    if ((bits < 160) || (bits > 1024)){ // [WARNING] THIS VALUE ARE NOT VERIFIED!!
                        // "Error: ECDSA/EdDSA/ECDH key size should be between 160 and 1024 bits.\n";
                        return false;
                    }
                }
                else{
                    // "Error: Unknown PKA " + std::to_string(subkey.pka) + " got through filter.\n";
                    return false;
                }
                #endif

                if (Sym::NAME.find(subkey.sym) == Sym::NAME.end()){
                    // "Error: Bad Symmetric Key Algorithm: " + std::to_string(subkey.sym);
                    return false;
                }

                if (Hash::NAME.find(subkey.hash) == Hash::NAME.end()){
                    // "Error: Bad Hash Algorithm: " + std::to_string(subkey.hash);
                    return false;
                }

                if (Hash::NAME.find(subkey.sig) == Hash::NAME.end()){
                    // "Error: Bad Hash Algorithm: " + std::to_string(subkey.sig);
                    return false;
                }

                if ((subkey.pka == PKA::ID::DSA) && (Hash::LENGTH.at(subkey.sig) < 256)){
                    // "Error: DSA needs a 256 bit or larger hash.\n";
                    return false;
                }
            }

            return true;
        }
    };

    // key generation using config defined above
    // returns a private key
    // public key can be extracted from the private key
    SecretKey generate_key(KeyGen & config);

}

#endif
