/*
revoke.h
Functions to revoke PGP keys

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

#ifndef __REVOKE__
#define __REVOKE__

#include <memory>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "Key.h"
#include "Misc/PKCS1.h"
#include "Misc/mpi.h"
#include "RevocationCertificate.h"
#include "sign.h"
#include "verify.h"

namespace OpenPGP {
    namespace Revoke {
        // check if a keyid has a revocation signature
        int check(const Key & key);

        // common arguments for revoking
        struct Args{
            SecretKey signer;
            std::string passphrase;
            Key target;                 // normally is the same key as signer
            uint8_t code;               // RFC 4880 sec 5.2.3.23. Reason for Revocation
            std::string reason;
            uint8_t version;            // 3 or 4
            uint8_t hash;

            Args(const SecretKey & sign,
                 const std::string & pass,
                 const Key & tar,
                 const uint8_t rev_code = Subpacket::Tag2::Revoke::NO_REASON_SPECIFIED,
                 const std::string & rev_reason = "",
                 const uint8_t ver = 4,
                 const uint8_t ha = Hash::ID::SHA1)
                : signer(sign),
                  passphrase(pass),
                  target(tar),
                  code(rev_code),
                  reason(rev_reason),
                  version(ver),
                  hash(ha)
            {}

            bool valid() const{
                if (!signer.meaningful()){
                    // "Error: Bad Signing Key.\n";
                    return false;
                }

                if (!target.meaningful()){
                    // "Error: Bad Target Key.\n";
                    return false;
                }

                if (Subpacket::Tag2::Revoke::NAME.find(code) == Subpacket::Tag2::Revoke::NAME.end()){
                    // "Error: Unknown revocation reason.\n";
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

        // 0x20: Key revocation signature
        // 0x28: Subkey revocation signature
        // 0x30: Certification revocation signature

        // Returns revocation signature packet
        Packet::Tag2::Ptr sig             (const Packet::Tag5::Ptr & signer, const std::string & passphrase, const Packet::Key::Ptr & target, Packet::Tag2::Ptr & sig);
        Packet::Tag2::Ptr key_sig         (const Args & args);
        Packet::Tag2::Ptr subkey_sig      (const Args & args, const std::string & keyid);
        Packet::Tag2::Ptr uid_sig         (const Packet::Tag5::Ptr & signer, const std::string & passphrase, const Packet::User::Ptr & user, Packet::Tag2::Ptr & sig);
        Packet::Tag2::Ptr uid_sig         (const Args & args, const std::string & ID);

        // creates revocation certificate to be used later
        RevocationCertificate key_cert    (const Args & args);
        RevocationCertificate subkey_cert (const Args & args, const std::string & keyid);
        RevocationCertificate uid_cert    (const Args & args, const std::string & ID);

        // Revoke with certificate
        PublicKey with_cert               (const Key & key, const RevocationCertificate & revoke);

        // Directly Revoke (does not write to key; instead, returns new copy of public key)
        PublicKey key                     (const Args & args);
        PublicKey subkey                  (const Args & args, const std::string & keyid);
        PublicKey uid                     (const Args & args, const std::string & ID);
    }
}
#endif
