/*
revoke.h
Functions to revoke PGP keys

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

#ifndef __REVOKE__
#define __REVOKE__

#include <memory>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "PGPKey.h"
#include "PGPRevocationCertificate.h"
#include "PKCS1.h"
#include "mpi.h"
#include "sign.h"
#include "verify.h"

// check if a keyid has a revocation signature
int check_revoked(const PGPKey & key, std::string & error);

// common arguments for revoking
struct RevArgs{
    PGPSecretKey signer;
    std::string passphrase;
    PGPKey target;              // normally is the same key as signer
    uint8_t code;               // RFC 4880 sec 5.2.3.23. Reason for Revocation
    std::string reason;
    uint8_t version;            // 3 or 4
    uint8_t hash;

    RevArgs(const PGPSecretKey & sign,
            const std::string & pass,
            const PGPKey & tar,
            const uint8_t rev_code = Revoke::NO_REASON_SPECIFIED,
            const std::string & rev_reason = "",
            const uint8_t ver = 4,
            const uint8_t ha = Hash::SHA1)
        : signer(sign),
          passphrase(pass),
          target(tar),
          code(rev_code),
          reason(rev_reason),
          version(ver),
          hash(ha)
    {}

    bool valid(std::string & error) const{
        if (!signer.meaningful(error)){
            error += "Error: Bad Signing Key.\n";
            return false;
        }

        if (!target.meaningful(error)){
            error += "Error: Bad Target Key.\n";
            return false;
        }

        if (Revoke::NAME.find(code) == Revoke::NAME.end()){
            error += "Error: Unknown revocation reason.\n";
            return false;
        }

        if ((version != 3) && (version != 4)){
            error += "Error: Bad version: " + std::to_string(version) + "\n";
            return false;
        }

        if (Hash::NAME.find(hash) == Hash::NAME.end()){
            error += "Error: Hash algorithm number " + std::to_string(hash) + " not found.\n";
            return false;
        }

        return true;
    }
};

// 0x20: Key revocation signature
// 0x28: Subkey revocation signature
// 0x30: Certification revocation signature

// Returns revocation signature packet
Tag2::Ptr revoke_sig                        (const Tag5::Ptr & signer, const std::string & passphrase, const Key::Ptr & target, Tag2::Ptr & sig, std::string & error);
Tag2::Ptr revoke_key_sig                    (const RevArgs & args, std::string & error);
Tag2::Ptr revoke_subkey_sig                 (const RevArgs & args, const std::string & keyid, std::string & error);
Tag2::Ptr revoke_uid_sig                    (const Tag5::Ptr & signer, const std::string & passphrase, const User::Ptr & user, Tag2::Ptr & sig, std::string & error);
Tag2::Ptr revoke_uid_sig                    (const RevArgs & args, const std::string & ID, std::string & error);

// creates revocation certificate to be used later
PGPRevocationCertificate revoke_key_cert    (const RevArgs & args, std::string & error);
PGPRevocationCertificate revoke_subkey_cert (const RevArgs & args, const std::string & keyid, std::string & error);
PGPRevocationCertificate revoke_uid_cert    (const RevArgs & args, const std::string & ID, std::string & error);

// Directly Revoke (does not write to key; instead, returns new copy of public key)
PGPPublicKey revoke_key                     (const RevArgs & args, std::string & error);
PGPPublicKey revoke_subkey                  (const RevArgs & args, const std::string & keyid, std::string & error);
PGPPublicKey revoke_uid                     (const RevArgs & args, const std::string & ID, std::string & error);

// Revoke key/subkey with certificate (not uid)
PGPPublicKey revoke_with_cert               (const PGPKey & key, const PGPRevocationCertificate & revoke, std::string & error);

#endif
