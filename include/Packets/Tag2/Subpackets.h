/*
Subpackets.h
List of Tag 2 Subpacket headers

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

#ifndef __TAG2_SUBPACKETS__
#define __TAG2_SUBPACKETS__

#include "Packets/Tag2/Subpacket.h"  // Base Type

#include "Packets/Tag2/Sub0.h"       // Reserved
#include "Packets/Tag2/Sub1.h"       // Reserved
#include "Packets/Tag2/Sub2.h"       // Signature Creation Time
#include "Packets/Tag2/Sub3.h"       // Signature Expiration Time
#include "Packets/Tag2/Sub4.h"       // Exportable Certification
#include "Packets/Tag2/Sub5.h"       // Trust Signature
#include "Packets/Tag2/Sub6.h"       // Regular Expression
#include "Packets/Tag2/Sub7.h"       // Revocable
#include "Packets/Tag2/Sub8.h"       // Reserved
#include "Packets/Tag2/Sub9.h"       // Key Expiration Time
#include "Packets/Tag2/Sub10.h"      // Placeholder for backward compatibility
#include "Packets/Tag2/Sub11.h"      // Preferred Symmetric Algorithms
#include "Packets/Tag2/Sub12.h"      // Revocation Key
#include "Packets/Tag2/Sub13.h"      // Reserved
#include "Packets/Tag2/Sub14.h"      // Reserved
#include "Packets/Tag2/Sub15.h"      // Reserved
#include "Packets/Tag2/Sub16.h"      // Issuer
#include "Packets/Tag2/Sub17.h"      // Reserved
#include "Packets/Tag2/Sub18.h"      // Reserved
#include "Packets/Tag2/Sub19.h"      // Reserved
#include "Packets/Tag2/Sub20.h"      // Notation Data
#include "Packets/Tag2/Sub21.h"      // Preferred Hash Algorithms
#include "Packets/Tag2/Sub22.h"      // Preferred Compression Algorithms
#include "Packets/Tag2/Sub23.h"      // Key Server Preferences
#include "Packets/Tag2/Sub24.h"      // Preferred Key Server
#include "Packets/Tag2/Sub25.h"      // Primary User ID
#include "Packets/Tag2/Sub26.h"      // Policy URI
#include "Packets/Tag2/Sub27.h"      // Key Flags
#include "Packets/Tag2/Sub28.h"      // Signer's User ID
#include "Packets/Tag2/Sub29.h"      // Reason for Revocation
#include "Packets/Tag2/Sub30.h"      // Features
#include "Packets/Tag2/Sub31.h"      // Signature Target
#include "Packets/Tag2/Sub32.h"      // Embedded Signature

#ifdef GPG_COMPATIBLE
#include "Packets/Tag2/Sub33.h"      // Issuer Fingerprint (GPG extension)
#endif

// 100 To 110           // Private or experimental

#endif
