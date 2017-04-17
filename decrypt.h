/*
decrypt.h
Functions for decrypting PGP encrypted data

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

#ifndef __DECRYPT__
#define __DECRYPT__

#include <string>

#include "Compress/Compress.h"
#include "Encryptions/Encryptions.h"
#include "Hashes/Hashes.h"
#include "Misc/PKCS1.h"
#include "Misc/cfb.h"
#include "Misc/mpi.h"
#include "PGPKey.h"
#include "PGPMessage.h"
#include "PKA/PKAs.h"
#include "Packets/packets.h"
#include "verify.h"

// decrypt data once session key is known
PGPMessage decrypt_data(const uint8_t sym,
                        const PGPMessage & message,
                        const std::string & session_key,
                        std::string & error);

// called from outside
// session key encrypted with public key algorithm
PGPMessage decrypt_pka(const PGPSecretKey & pri,
                       const std::string & passphrase,
                       const PGPMessage & message,
                       std::string & error);

// session key encrypted with symmetric algorithm
PGPMessage decrypt_sym(const PGPMessage & message,
                       const std::string & passphrase,
                       std::string & error);

#endif
