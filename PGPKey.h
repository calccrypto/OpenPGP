/*
PGPKey.h
OpenPGP Transferable key data structure (RFC 4880 sec 11.1 and 11.2)

Copyright (c) 2013, 2014 Jason Lee

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

#ifndef __PGP_KEY__
#define __PGP_KEY__

#include "Packets/packets.h"
#include "PGP.h"

class PGPKey : public PGP {
    /*
    11.1. Transferable Public Keys

        OpenPGP users may transfer public keys. The essential elements of a
        transferable public key are as follows:

            - One Public-Key packet
            - Zero or more revocation signatures
            - One or more User ID packets
            - After each User ID packet, zero or more Signature packets (certifications)
            - Zero or more User Attribute packets
            - After each User Attribute packet, zero or more Signature packets (certifications)
            - Zero or more Subkey packets
            - After each Subkey packet, one Signature packet, plus optionally a revocation
    */

    protected:
        bool meaningful(uint8_t tag) const;

    public:
        typedef std::shared_ptr <PGPKey> Ptr;

        PGPKey();
        PGPKey(const PGPKey & copy);
        PGPKey(std::string & data);
        PGPKey(std::ifstream & f);
        ~PGPKey();

        std::string keyid() const;           // keyid that is searched for on keyservers
        std::string list_keys() const;       // output is copied from gpg --list-keys
        virtual bool meaningful() const;     // whether or not data matches PGP Transferable Key format

        virtual PGP::Ptr clone() const;
};

std::ostream & operator <<(std::ostream & stream, const PGPKey & pgp);

class PGPPublicKey;

class PGPSecretKey : public PGPKey {
    public:
        typedef std::shared_ptr <PGPSecretKey> Ptr;

        PGPSecretKey();
        PGPSecretKey(const PGPSecretKey & copy);
        PGPSecretKey(std::string & data);
        PGPSecretKey(std::ifstream & f);
        ~PGPSecretKey();

        PGPPublicKey pub() const;

        bool meaningful() const;

        PGP::Ptr clone() const;
};

std::ostream & operator <<(std::ostream & stream, const PGPSecretKey & pgp);

class PGPPublicKey : public PGPKey {
    public:
        typedef std::shared_ptr <PGPPublicKey> Ptr;

        PGPPublicKey();
        PGPPublicKey(const PGPPublicKey & copy);
        PGPPublicKey(std::string & data);
        PGPPublicKey(std::ifstream & f);
        PGPPublicKey(const PGPSecretKey & sec);
        ~PGPPublicKey();

        bool meaningful() const;

        PGP::Ptr clone() const;
};

std::ostream & operator <<(std::ostream & stream, const PGPPublicKey & pgp);

// Extract Public Key data from a Secret Key
PGPPublicKey Secret2PublicKey(const PGPSecretKey & pri);

// Search PGP keys for signing keys
// leave keyid empty to find the signing key without matching the key id
Key::Ptr find_signing_key(const PGPKey::Ptr & key, const uint8_t tag, const std::string & keyid = "");
Tag6::Ptr find_signing_key(const PGPPublicKey & key, const uint8_t tag, const std::string & keyid = "");
Tag5::Ptr find_signing_key(const PGPSecretKey & key, const uint8_t tag, const std::string & keyid = "");
#endif