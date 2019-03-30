/*
Status.h
List of possible statuses returned by OpenPGP

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

#ifndef __OPENPGP_STATUS__
#define __OPENPGP_STATUS__

namespace OpenPGP {
    enum Status {
        SUCCESS,
        INVALID,
        INVALID_COMPRESSION_ALGORITHM,  // Tag 8, Tag 2 Sub 22
        INVALID_CONTENTS,
        INVALID_FINGERPRINT,
        INVALID_FLAG,                   // Generic error for other flags
        INVALID_HASH_ALGORITHM,
        INVALID_LEFT16_BITS,            // Tag 2
        INVALID_LENGTH,
        INVALID_LITERAL_DATA_FORMAT,    // Tag 11
        INVALID_MPI_COUNT,
        INVALID_PUBLIC_KEY_ALGORITHM,
        INVALID_REASON_FOR_REVOCATION,  // Tag 2 Sub 29
        INVALID_SHA1_HASH,              // Tag 18
        INVALID_SIGNATURE_TYPE,
        INVALID_SYMMETRIC_ENCRYPTION_ALGORITHM,
        INVALID_TAG,
        INVALID_VERSION,
        MISSING_S2K,                    // Tag 3, 5
        PKA_CANNOT_BE_USED,
        REGEX_ERROR,                    // Tag 2 Sub 6
        RESERVED,
        SHOULD_NOT_BE_EMITTED,          // Tag 12
        WRONG_S2K_TYPE,
    };
}

#endif
