/*
PKCS1.h
PKCS#1 as decrypted in RFC 4880 sec 13.1

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

#ifndef __PKCS1__
#define __PKCS1__

#include "Hashes/Hashes.h"

namespace OpenPGP {

    // 13.1.1.  EME-PKCS1-v1_5-ENCODE
    //
    //    Input:
    //
    //    k  = the length in octets of the key modulus
    //
    //    M  = message to be encoded, an octet string of length mLen, where
    //         mLen <= k - 11
    //
    //    Output:
    //
    //    EM = encoded message, an octet string of length k
    //
    //    Error:   "message too long"
    //
    //      1. Length checking: If mLen > k - 11, output "message too long" and
    //         stop.
    //
    //      2. Generate an octet string PS of length k - mLen - 3 consisting of
    //         pseudo-randomly generated nonzero octets.  The length of PS will
    //         be at least eight octets.
    //
    //      3. Concatenate PS, the message M, and other padding to form an
    //         encoded message EM of length k octets as
    //
    //         EM = 0x00 || 0x02 || PS || 0x00 || M.
    //
    //      4. Output EM.

    std::string EME_PKCS1v1_5_ENCODE(const std::string & m, const unsigned int & k);

    // 13.1.2.  EME-PKCS1-v1_5-DECODE
    //
    //    Input:
    //
    //    EM = encoded message, an octet string
    //
    //    Output:
    //
    //    M  = message, an octet string
    //
    //    Error:   "decryption error"
    //
    //    To decode an EME-PKCS1_v1_5 message, separate the encoded message EM
    //    into an octet string PS consisting of nonzero octets and a message M
    //    as follows
    //
    //      EM = 0x00 || 0x02 || PS || 0x00 || M.
    //
    //    If the first octet of EM does not have hexadecimal value 0x00, if the
    //    second octet of EM does not have hexadecimal value 0x02, if there is
    //    no octet with hexadecimal value 0x00 to separate PS from M, or if the
    //    length of PS is less than 8 octets, output "decryption error" and
    //    stop.  See also the security note in Section 14 regarding differences
    //    in reporting between a decryption error and a padding error.

    std::string EME_PKCS1v1_5_DECODE(const std::string & m);

    // 13.1.3.  EMSA-PKCS1-v1_5
    //
    //    This encoding method is deterministic and only has an encoding
    //    operation.
    //
    //    Option:
    //
    //    Hash - a hash function in which hLen denotes the length in octets of
    //          the hash function output
    //
    //    Input:
    //
    //    M  = message to be encoded
    //
    //    mL = intended length in octets of the encoded message, at least tLen
    //         + 11, where tLen is the octet length of the DER encoding T of a
    //         certain value computed during the encoding operation
    //
    //    Output:
    //
    //    EM = encoded message, an octet string of length emLen
    //
    //    Errors: "message too long"; "intended encoded message length too
    //    short"
    //
    //    Steps:
    //
    //      1. Apply the hash function to the message M to produce a hash value
    //         H:
    //
    //         H = Hash(M).
    //
    //         If the hash function outputs "message too long," output "message
    //         too long" and stop.
    //
    //      2. Using the list in Section 5.2.2, produce an ASN.1 DER value for
    //         the hash function used.  Let T be the full hash prefix from
    //         Section 5.2.2, and let tLen be the length in octets of T.
    //
    //      3. If emLen < tLen + 11, output "intended encoded message length
    //         too short" and stop.
    //
    //      4. Generate an octet string PS consisting of emLen - tLen - 3
    //         octets with hexadecimal value 0xFF.  The length of PS will be at
    //         least 8 octets.
    //
    //      5. Concatenate PS, the hash prefix T, and other padding to form the
    //         encoded message EM as
    //
    //         EM = 0x00 || 0x01 || PS || 0x00 || T.
    //
    //      6. Output EM.

    std::string EMSA_PKCS1_v1_5(const uint8_t & hash, const std::string & hashed_data, const unsigned int & keylength);

}

#endif
