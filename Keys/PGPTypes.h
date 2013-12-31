/*
PGPTypes.h
List of PGP Data Structures

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

#ifndef __PGP_TYPES__
#define __PGP_TYPES__

#include "PGP.h"                    // Base class

#include "PGPMessage.h"             // Used for signed, encrypted, or compressed files.

#include "PGPKey.h"                 // Child of PGP, Parent of PGPPublicKey and PGPPrivateKey
#include "PGPPublicKey.h"           // Public Key class
#include "PGPPrivateKey.h"          // Private Key class

#include "PGPMessageXY.h"           // Used for multi-part messages, where the armor is split amongst Y parts, and this is the Xth part out of Y.
#include "PGPMessageX.h"            // Used for multi-part messages, where this is the Xth part of an unspecified number of parts. Requires the MESSAGE-ID Armor Header to be used.

#include "PGPSignature.h"           // Used for detached signatures, OpenPGP/MIME signatures, and cleartext signatures. Note that PGP 2.x uses BEGIN PGP MESSAGE for detached signatures.

#include "PGPSignedMessage.h"       // Used for signed messages; not part of RFC 4880

#endif
