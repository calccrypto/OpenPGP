/*
verify.c
Functions to verify data signed by a PGP key

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

#ifndef __VERIFY__
#define __VERIFY__

#include <string>

#include "CleartextSignature.h"
#include "DetachedSignature.h"
#include "Key.h"
#include "Message.h"
#include "Misc/PKCS1.h"
#include "Misc/mpi.h"
#include "Misc/sigcalc.h"
#include "PKA/PKAs.h"
#include "Packets/Packets.h"
#include "RevocationCertificate.h"

namespace OpenPGP {
    namespace Verify {
        // verify pka with variables only
        int with_pka(const std::string & digest, const uint8_t hash, const uint8_t pka, const PKA::Values & signer, const PKA::Values & signee);

        // verify pka with packets
        int with_pka(const std::string & digest, const Packet::Key::Ptr & signer, const Packet::Tag2::Ptr & signee);
        // /////////////////

        // detached signatures (not a standalone signature)
        int detached_signature(const Key & key, const std::string & data, const DetachedSignature & sig);

        // 0x00: Signature of a binary document.
        int binary(const Key & key, const Message & message);

        // 0x01: Signature of a canonical text document.
        int cleartext_signature(const Key & pub, const CleartextSignature & message);

        // 0x02: Standalone signature.

        // 0x10: Generic certification of a User ID and Public-Key packet.
        // 0x11: Persona certification of a User ID and Public-Key packet.
        // 0x12: Casual certification of a User ID and Public-Key packet.
        // 0x13: Positive certification of a User ID and Public-Key packet.
        int primary_key(const Packet::Key::Ptr & signer_key, const Packet::Key::Ptr & signee_key, const Packet::User::Ptr & signee_id, const Packet::Tag2::Ptr & signee_signature);
        int primary_key(const Key & signer, const Key & signee);

        // 0x18: Subkey Binding Signature

        // 0x19: Primary Key Binding Signature

        // 0x1F: Signature directly on a key

        // 0x20: Key revocation signature
        // 0x28: Subkey revocation signature
        // 0x30: Certification revocation signature
        int revoke(const Key & key, const RevocationCertificate & revoke);

        // 0x40: Timestamp signature.
        int timestamp(const Key & key, const DetachedSignature & timestamp);

        // 0x50: Third-Party Confirmation signature.
    }
}

#endif
