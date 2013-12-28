/*
verify.c
Functions to verify data signed by a PGP key

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

#include <fstream>
#include <iostream>
#include <sstream>

#include <gmpxx.h>

#include "PKA/PKA.h"
#include "OpenPGP.h"
#include "sigcalc.h"

#ifndef __VERIFY__
#define __VERIFY__

std::string find_keyid(Tag2 * tag2);
std::vector <mpz_class> find_matching_pub_key(std::string keyid, PGP & key);

bool pka_verify(std::string & hashed_message, Tag2 * tag2, std::vector <mpz_class> & key);

// Use string.size() to check if input was verified.
bool verify_file(std::string filename, PGP & sig, PGP & key);
bool verify_file(std::ifstream & f, PGP & sig, PGP & key);

bool verify_message(PGPMessage & message, PGP & key);
bool verify_signature(PGP & sig, PGP & key);
bool verify_revoke(PGP & key, PGP & rev);
#endif
