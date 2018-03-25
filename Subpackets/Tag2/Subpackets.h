/*
Subpackets.h
List of Tag 2 Subpacket headers

Copyright (c) 2013 - 2018 Jason Lee @ calccrypto at gmail.com

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

#ifndef __TAG2_SUBPACKETS__
#define __TAG2_SUBPACKETS__

#include "Subpacket.h"  // Base Type

#include "Sub0.h"       // Reserved
#include "Sub1.h"       // Reserved
#include "Sub2.h"       // Signature Creation Time
#include "Sub3.h"       // Signature Expiration Time
#include "Sub4.h"       // Exportable Certification
#include "Sub5.h"       // Trust Signature
#include "Sub6.h"       // Regular Expression
#include "Sub7.h"       // Revocable
#include "Sub8.h"       // Reserved
#include "Sub9.h"       // Key Expiration Time
#include "Sub10.h"      // Placeholder for backward compatibility
#include "Sub11.h"      // Preferred Symmetric Algorithms
#include "Sub12.h"      // Revocation Key
#include "Sub13.h"      // Reserved
#include "Sub14.h"      // Reserved
#include "Sub15.h"      // Reserved
#include "Sub16.h"      // Issuer
#include "Sub17.h"      // Reserved
#include "Sub18.h"      // Reserved
#include "Sub19.h"      // Reserved
#include "Sub20.h"      // Notation Data
#include "Sub21.h"      // Preferred Hash Algorithms
#include "Sub22.h"      // Preferred Compression Algorithms
#include "Sub23.h"      // Key Server Preferences
#include "Sub24.h"      // Preferred Key Server
#include "Sub25.h"      // Primary User ID
#include "Sub26.h"      // Policy URI
#include "Sub27.h"      // Key Flags
#include "Sub28.h"      // Signer's User ID
#include "Sub29.h"      // Reason for Revocation
#include "Sub30.h"      // Features
#include "Sub31.h"      // Signature Target
#include "Sub32.h"      // Embedded Signature

#ifdef GPG_COMPATIBLE
#include "Sub33.h"      // Issuer Fingerprint (GPG extension)
#endif

// 100 To 110           // Private or experimental

#endif
