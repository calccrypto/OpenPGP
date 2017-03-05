/*
Subpackets.h
List of all subpacket headers

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

#ifndef __SUBPACKETS__
#define __SUBPACKETS__

#include "subpacket.h"      

#include "Tag2Subpacket.h"  // 5.2.3.1 Signature Subpacket Specification

#include "Tag2Sub0.h"       // Reserved
#include "Tag2Sub1.h"       // Reserved
#include "Tag2Sub2.h"       // Signature Creation Time
#include "Tag2Sub3.h"       // Signature Expiration Time
#include "Tag2Sub4.h"       // Exportable Certification
#include "Tag2Sub5.h"       // Trust Signature
#include "Tag2Sub6.h"       // Regular Expression
#include "Tag2Sub7.h"       // Revocable
#include "Tag2Sub8.h"       // Reserved
#include "Tag2Sub9.h"       // Key Expiration Time
#include "Tag2Sub10.h"      // Placeholder for backward compatibility
#include "Tag2Sub11.h"      // Preferred Symmetric Algorithms
#include "Tag2Sub12.h"      // Revocation Key
#include "Tag2Sub13.h"      // Reserved
#include "Tag2Sub14.h"      // Reserved
#include "Tag2Sub15.h"      // Reserved
#include "Tag2Sub16.h"      // Issuer
#include "Tag2Sub17.h"      // Reserved
#include "Tag2Sub18.h"      // Reserved
#include "Tag2Sub19.h"      // Reserved
#include "Tag2Sub20.h"      // Notation Data
#include "Tag2Sub21.h"      // Preferred Hash Algorithms
#include "Tag2Sub22.h"      // Preferred Compression Algorithms
#include "Tag2Sub23.h"      // Key Server Preferences
#include "Tag2Sub24.h"      // Preferred Key Server
#include "Tag2Sub25.h"      // Primary User ID
#include "Tag2Sub26.h"      // Policy URI
#include "Tag2Sub27.h"      // Key Flags
#include "Tag2Sub28.h"      // Signer's User ID
#include "Tag2Sub29.h"      // Reason for Revocation
#include "Tag2Sub30.h"      // Features
#include "Tag2Sub31.h"      // Signature Target
#include "Tag2Sub32.h"      // Embedded Signature
// 100 To 110               // Private or experimental

#include "Tag17Subpacket.h" // 5.12. User Attribute Packet (Tag 17)

#include "Tag17Sub1.h"      // Image Attribute

#endif
