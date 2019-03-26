/*
Packets.h
Main packets and related functions include file

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

#ifndef __PACKETS__
#define __PACKETS__

#include "Packets/Packet.h"

#include "Packets/Key.h"      // for Tags 5, 6, 7, and 14
#include "Packets/Partial.h"  // for Tags 8, 9, 11, and 18
#include "Packets/User.h"     // for Tags 13 and 17

#include "Packets/Tag0.h"     // Reserved - a packet tag MUST NOT have this value
#include "Packets/Tag1.h"     // Public-Key Encrypted Session Key
#include "Packets/Tag2.h"     // Signature
#include "Packets/Tag3.h"     // Symmetric-Key Encrypted Session Key
#include "Packets/Tag4.h"     // One-Pass Signature
#include "Packets/Tag5.h"     // Secret-Key
#include "Packets/Tag6.h"     // Public-Key
#include "Packets/Tag7.h"     // Secret-Subkey
#include "Packets/Tag8.h"     // Compressed Data
#include "Packets/Tag9.h"     // Symmetrically (Conventional) Encrypted Data
#include "Packets/Tag10.h"    // Marker Packet (Obsolete Literal Packet)
#include "Packets/Tag11.h"    // Literal Data
#include "Packets/Tag12.h"    // (Keyring) Trust
#include "Packets/Tag13.h"    // User ID
#include "Packets/Tag14.h"    // Pubic-Subkey (Obsolete COmment Packet)
#include "Packets/Tag17.h"    // User Attribute
#include "Packets/Tag18.h"    // Sym. Encrypted Integrity Protected Data
#include "Packets/Tag19.h"    // Modification Detection Code
#include "Packets/Tag60.h"    // Private or Experimental Values
#include "Packets/Tag61.h"    // Private or Experimental Values
#include "Packets/Tag62.h"    // Private or Experimental Values
#include "Packets/Tag63.h"    // Private or Experimental Values

#endif
