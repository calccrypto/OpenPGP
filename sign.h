/*
sign.h
Function to sign some data with a PGP key

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

#include "common/includes.h"
#include "Packets/packets.h"
#include "PKA/DSA.h"
#include "PKA/RSA.h"
#include "decrypt.h"
#include "pgptime.h"

#ifndef __SIGN__
#define __SIGN__
// Extract private key data
Tag5 * find_signing_packet(PGP & k);
Tag13 * find_signer_id(PGP & k);

std::vector <mpz_class> pka_sign(std::string hashed_message, uint8_t pka, std::vector <mpz_class> & pub, std::vector <mpz_class> & pri);

// Will generate new default Signature packet if none is given.
// Only signs data. Output is essentially a detached signature.
Tag2 * sign(uint8_t type, std::string hashed_data, Tag5 * tag5, std::string pass, Tag2 * tag2 = NULL);
#endif
