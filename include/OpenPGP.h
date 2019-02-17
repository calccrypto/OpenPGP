/*
OpenPGP.h
Single file to include to get all of OpenPGP

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

// OpenPGP Types
#include "PGP.h"                   // abstract base class
#include "CleartextSignature.h"    // Cleartext Signatures
#include "DetachedSignature.h"     // Detached Signatures
#include "Key.h"                   // Transferable Keys
#include "Message.h"               // OpenPGP Messages
#include "RevocationCertificate.h" // OpenPGP Messages

// OpenPGP Functions
#include "decrypt.h"               // decrypt stuff
#include "encrypt.h"               // encrypt stuff
#include "keygen.h"                // generate OpenPGP keys
#include "revoke.h"                // revoke OpenPGP keys
#include "sign.h"                  // sign stuff
#include "verify.h"                // verify signatures
