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

        virtual PGP::Ptr clone() const;
        
        virtual bool meaningful() const;
};

class PGPSecretKey : public PGPKey {
    public:
        typedef std::shared_ptr <PGPSecretKey> Ptr;

        PGPSecretKey();
        PGPSecretKey(const PGPSecretKey & copy);
        PGPSecretKey(std::string & data);
        PGPSecretKey(std::ifstream & f);
        ~PGPSecretKey();

        PGP::Ptr clone() const;
        
        bool meaningful() const;
};

class PGPPublicKey : public PGPKey {
    public:
        typedef std::shared_ptr <PGPPublicKey> Ptr;

        PGPPublicKey();
        PGPPublicKey(const PGPPublicKey & copy);
        PGPPublicKey(std::string & data);
        PGPPublicKey(std::ifstream & f);
        PGPPublicKey(const PGPSecretKey & sec);
        ~PGPPublicKey();
        
        PGP::Ptr clone() const;

        bool meaningful() const;
};


#endif