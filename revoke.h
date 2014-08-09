/*
revoke.h
Functions to revoke PGP keys

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

#ifndef __REVOKE__
#define __REVOKE__

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "mpi.h"
#include "PGPKey.h"
#include "PKCS1.h"
#include "sign.h"
#include "verify.h"

// check if a key has been revoked
bool check_revoked(const std::vector <Packet::Ptr> & packets, const std::string & keyid);
bool check_revoked(const PGPPublicKey & pub, const std::string & keyid);
bool check_revoked(const PGPSecretKey & pri, const std::string & keyid);

// main function to revoke a primary key
Tag2::Ptr revoke_primary_key_cert(PGPSecretKey & pri, const std::string & passphrase, const uint8_t code, const std::string & reason = "");
// packages certification into a key
PGPPublicKey revoke_primary_key_cert_key(PGPSecretKey & pri, const std::string & passphrase, const uint8_t code, const std::string & reason = "");

// main function to revoke a subkey
Tag2::Ptr revoke_subkey_cert(PGPSecretKey & pri, const std::string & passphrase, const uint8_t code, const std::string & reason = "");
// packages certification into a key
PGPPublicKey revoke_subkey_cert_key(PGPSecretKey & pri, const std::string & passphrase, const uint8_t code, const std::string & reason = "");

// 0x30
PGPPublicKey revoke_uid(PGPPublicKey & pub, PGPSecretKey & pri, const std::string passphrase, const uint8_t code, const std::string & reason = "");

// Directly Revoke Something
PGPPublicKey revoke_key(PGPSecretKey & pri, const std::string & passphrase, const uint8_t code, const std::string & reason = "");
PGPPublicKey revoke_subkey(PGPSecretKey & pri, const std::string & passphrase, const uint8_t code, const std::string & reason = "");

// Revoke with certificate
PGPPublicKey revoke_with_cert(const PGPPublicKey & pub, PGPPublicKey & revoke);
PGPPublicKey revoke_with_cert(const PGPSecretKey & pri, PGPPublicKey & revoke);

#endif
