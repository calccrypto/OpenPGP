/*
decrypt.h
Functions for decrypting PGP encrypted data

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

#include <gmpxx.h>

#include "Keys/PGPTypes.h"
#include "Packets/packets.h"
#include "PKA/PKA.h"
#include "cfb.h"
#include "consts.h"
#include "PKCS1.h"
#include "usehash.h"

#ifndef __DECRYPT__
#define __DECRYPT__
Tag5 * find_encrypting_key(PGP & k);
std::string pka_decrypt(const uint8_t pka, std::vector <mpz_class> & data, const std::vector <mpz_class> & pri, const std::vector <mpz_class> & pub = {});
std::vector <mpz_class> decrypt_secret_key(Tag5 * pri, const std::string & passphrase);
std::string decrypt_message(PGP & m, PGP & pri, const std::string & passphrase);
#endif
