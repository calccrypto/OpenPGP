/*
sign.h
Functions to sign some data with a PGP key

Copyright (c) 2013 Jason Lee

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

#include <iostream>
#include <vector>

#include <gmpxx.h>

#include "common/includes.h"
#include "Packets/packets.h"
#include "PKA/PKA.h"
#include "OpenPGP.h"
#include "decrypt.h"
#include "pgptime.h"
#include "sigcalc.h"

#ifndef __SIGN__
#define __SIGN__
// Extract private key data
Tag5 * find_signing_packet(PGP & k);
Tag13 * find_signer_id(PGP & k);

std::vector <mpz_class> pka_sign(const std::string & hashed_data, uint8_t pka, std::vector <mpz_class> & pub, std::vector <mpz_class> & pri);
std::vector <mpz_class> pka_sign(const std::string & hashed_data, Tag5 * tag5, std::string pass);

// Generates new default signature packet
Tag2 * create_sig_packet(const uint8_t type, PGP & key);

// Creates detatched signatures
PGP sign_file(const std::string & data, PGP & key, const std::string & passphrase);
PGP sign_file(std::ifstream & f, PGP & key, const std::string &  passphrase);
PGPMessage sign_message(const std::string & text, PGP & key, const std::string passphrase);
#endif
