/*
consts.h
OpenPGP Global Values - Defined in RFC4880 and referred RFCs and a few of my own definitions

Copyright (c) 2013, 2014 Jason Lee

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

#ifndef __PGP_CONSTS__
#define __PGP_CONSTS__

#include <cstdint>
#include <iostream>
#include <map>
#include <utility>

// ASCII data at beginning and end of OpenPGP packet
const std::string ASCII_Armor_Header[7] = {
               "MESSAGE",                               // Used for signed, encrypted, or compressed files.
               "PUBLIC KEY BLOCK",                      // Used for armoring public keys.
               "PRIVATE KEY BLOCK",                     // Used for armoring private keys.
               "MESSAGE, PART X/Y",                     // Used for multi-part messages, where the armor is split amongst Y parts, and this is the Xth part out of Y.
               "MESSAGE, PART X",                       // Used for multi-part messages, where this is the Xth part of an unspecified number of parts. Requires the MESSAGE-ID Armor Header to be used.
               "SIGNATURE",                             // Used for detached signatures, OpenPGP/MIME signatures, and cleartext signatures. Note that PGP 2.x uses BEGIN PGP MESSAGE for detached signatures.
               "SIGNED MESSAGE",                        // Used for cleartext signatures; header not really part of RFC 4880.
};

// ASCII descriptor of OpenPGP packet
const std::string ASCII_Armor_Key[5] = {
                "Version",                              // which states the OpenPGP implementation and version used to encode the message.

                "Comment",                              // a user-defined comment. OpenPGP defines all text to be in UTF-8. A comment may be any UTF-8 string. However, the whole point of armoring is to provide seven-bit-clean data.
                                                        // Consequently, if a comment has characters that are outside the US-ASCII range of UTF, they may very well not survive transport.

                "MessageID",                            // a 32-character string of printable characters. The string must be the same for all parts of a multi-part message that uses the "PART X" Armor Header. MessageID strings should be
                                                        // unique enough that the recipient of the mail can associate all the parts of a message with each other. A good checksum or cryptographic hash function is sufficient.
                                                        // The MessageID SHOULD NOT appear unless it is in a multi-part message. If it appears at all, it MUST be computed from the finished (encrypted, signed, etc.) message in a deterministic
                                                        // fashion, rather than contain a purely random value. This is to allow the legitimate recipient to determine that the MessageID cannot serve as a covert means of leaking cryptographic key
                                                        // information.

                "Hash",                                 // a comma-separated list of hash algorithms used in this message. This is used only in cleartext signed messages.

                "Charset",                              // a description of the character set that the plaintext is in. Please note that OpenPGP defines text to be in UTF-8. An implementation will get best results by translating into and out
};

// Binary, Text or UTF-8
const std::map <uint8_t, std::string> BTU = {
                std::make_pair(0x62, "Binary"),
                std::make_pair(0x74, "Text"),
                std::make_pair(0x75, "UTF-8 Text"),
};

// Binary, Text or UTF-8
const std::map <uint8_t, std::string> Compression_Algorithms = {
                std::make_pair(0, "UNCOMPRESSED"),
                std::make_pair(1, "ZIP {RFC1951}"),
                std::make_pair(2, "ZLIB {RFC1950}"),
                std::make_pair(3, "BZip2 {BZ2}"),
                std::make_pair(100, "Private/Experimental algorithm"),
                std::make_pair(101, "Private/Experimental algorithm"),
                std::make_pair(102, "Private/Experimental algorithm"),
                std::make_pair(103, "Private/Experimental algorithm"),
                std::make_pair(104, "Private/Experimental algorithm"),
                std::make_pair(105, "Private/Experimental algorithm"),
                std::make_pair(106, "Private/Experimental algorithm"),
                std::make_pair(107, "Private/Experimental algorithm"),
                std::make_pair(108, "Private/Experimental algorithm"),
                std::make_pair(109, "Private/Experimental algorithm"),
                std::make_pair(110, "Private/Experimental algorithm"),
};

// Reverse Compression_Algorithms
const std::map <std::string, uint8_t> Compression_Numbers = {
                std::make_pair("UNCOMPRESSED", 0),
                std::make_pair("ZIP", 1),
                std::make_pair("ZLIB", 2),
                std::make_pair("BZip2", 3),
                // can't really reverse map 100 - 110
};

const std::string dayofweek[7] = {"Sun", "Mon", "Tues", "Wed", "Thur", "Fri", "Sat"};

// Features Flags
const std::map <uint8_t, std::string> Features = {
                std::make_pair(1, "Modification Detection (packets 18 and 19)"),        // Only defined value; Others can be added if desired. Others will eventually be added
};

// Key Flags
const std::map <uint8_t, std::string> Flags = {
                std::make_pair(1, "This key may be used to certify other keys"),
                std::make_pair(2, "This key may be used to sign data"),
                std::make_pair(4, "This key may be used to encrypt communications"),
                std::make_pair(8, "This key may be used to encrypt storage"),
                std::make_pair(16, "The private component of this key may have been split by a secret-sharing mechanism"),
                std::make_pair(32, "This key may be used for authentication"),
                std::make_pair(0x80, "The private component of this key may be in the possession of more than one person"),
};

// Hash Tags
const std::map <uint8_t, std::string> Hash_Algorithms = {
                std::make_pair(1, "MD5"),
                std::make_pair(2, "SHA1"),
                std::make_pair(3, "RIPEMD160"),
                std::make_pair(4, "Reserved"),
                std::make_pair(5, "Reserved"),
                std::make_pair(6, "Reserved"),
                std::make_pair(7, "Reserved"),
                std::make_pair(8, "SHA256"),
                std::make_pair(9, "SHA384"),
                std::make_pair(10, "SHA512"),
                std::make_pair(11, "SHA224"),
                std::make_pair(100, "Private/Experimental algorithm"),
                std::make_pair(101, "Private/Experimental algorithm"),
                std::make_pair(102, "Private/Experimental algorithm"),
                std::make_pair(103, "Private/Experimental algorithm"),
                std::make_pair(104, "Private/Experimental algorithm"),
                std::make_pair(105, "Private/Experimental algorithm"),
                std::make_pair(106, "Private/Experimental algorithm"),
                std::make_pair(107, "Private/Experimental algorithm"),
                std::make_pair(108, "Private/Experimental algorithm"),
                std::make_pair(109, "Private/Experimental algorithm"),
                std::make_pair(110, "Private/Experimental algorithm"),
};

// Reverse Hash_Algorithms
const std::map <std::string, uint8_t> Hash_Numbers = {
                std::make_pair("MD5", 1),
                std::make_pair("SHA1", 2),
                std::make_pair("RIPEMD160", 3),
                std::make_pair("SHA256", 8),
                std::make_pair("SHA384", 9),
                std::make_pair("SHA512", 10),
                std::make_pair("SHA224", 11),
};

// ASN.1 OIDs in hex form
const std::map <std::string, std::string> Hash_ASN1_DER = {
                std::make_pair("MD5",       "3020300C06082A864886F70D020505000410"),         // 1.2.840.113549.2.5
                std::make_pair("RIPEMD160", "3021300906052B2403020105000414"),               // 1.3.36.3.2.1
                std::make_pair("SHA1",      "3021300906052B0E03021A05000414"),               // 1.3.14.3.2.26
                std::make_pair("SHA224",    "302D300d06096086480165030402040500041C"),       // 2.16.840.1.101.3.4.2.4
                std::make_pair("SHA256",    "3031300d060960864801650304020105000420"),       // 2.16.840.1.101.3.4.2.1
                std::make_pair("SHA384",    "3041300d060960864801650304020205000430"),       // 2.16.840.1.101.3.4.2.2
                std::make_pair("SHA512",    "3051300d060960864801650304020305000440"),       // 2.16.840.1.101.3.4.2.3
};

// Length of defined hash outputs in bits
const std::map <std::string, uint16_t> Hash_Length = {
                std::make_pair("MD5", 128),
                std::make_pair("SHA1", 160),
                std::make_pair("RIPEMD160", 160),
                std::make_pair("SHA256", 256),
                std::make_pair("SHA384", 384),
                std::make_pair("SHA512", 512),
                std::make_pair("SHA224", 224),
};

// Key Server Preferences Tags
const std::map <uint8_t, std::string> Key_Server_Preferences = {
                std::make_pair(0x00, ""),
                std::make_pair(0x80, "No-modify"),
};

const std::string month[12] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sept", "Oct", "Nov", "Dec"};

// Notation on signature issuer wishes to make
const std::map <uint8_t, std::string> Notation = {
                std::make_pair(0x00, ""),
                std::make_pair(0x80, "Human-dumpable"),
};

// Packet Tags
const std::map <uint8_t, std::string> Packet_Tags = {
                std::make_pair(0, "Reserved - a packet tag MUST NOT have this value"),
                std::make_pair(1, "Public-Key Encrypted Session Key"),
                std::make_pair(2, "Signature"),
                std::make_pair(3, "Symmetric-Key Encrypted Session Key"),
                std::make_pair(4, "One-Pass Signature"),
                std::make_pair(5, "Secret-Key"),
                std::make_pair(6, "Public-Key"),
                std::make_pair(7, "Secret-Subkey"),
                std::make_pair(8, "Compressed Data"),
                std::make_pair(9, "Symmetrically (Conventional) Encrypted Data"),
                std::make_pair(10, "Marker Packet (Obsolete Literal Packet)"),
                std::make_pair(11, "Literal Data"),
                std::make_pair(12, "(Keyring) Trust"),
                std::make_pair(13, "User ID"),
                std::make_pair(14, "Public-Subkey (Obsolete Comment Packet)"),
                std::make_pair(17, "User Attribute"),
                std::make_pair(18, "Sym. Encrypted Integrity Protected Data"),
                std::make_pair(19, "Modification Detection Code"),
                std::make_pair(60, "Private or Experimental Values"),
                std::make_pair(61, "Private or Experimental Values"),
                std::make_pair(62, "Private or Experimental Values"),
                std::make_pair(63, "Private or Experimental Values"),
};

// Public Key Algorithm
const std::map <uint8_t, std::string> Public_Key_Algorithms = {
                std::make_pair(1, "RSA (Encrypt or Sign)"),
                std::make_pair(2, "RSA Encrypt-Only"),                                         // deprecated
                std::make_pair(3, "RSA Sign-Only"),                                            // deprecated
                std::make_pair(16, "ElGamal (Encrypt-Only)"),
                std::make_pair(17, "DSA"),
                std::make_pair(18, "Reserved for Elliptic Curve"),
                std::make_pair(19, "Reserved for ECDSA"),
                std::make_pair(20, "Reserved (formerly ElGamal Encrypt or Sign)"),
                std::make_pair(21, "Reserved for Diffie-Hellman (X9.42), as defined for IETF-S / MIME)"),
                std::make_pair(100, "Private/Experimental algorithm"),
                std::make_pair(101, "Private/Experimental algorithm"),
                std::make_pair(102, "Private/Experimental algorithm"),
                std::make_pair(103, "Private/Experimental algorithm"),
                std::make_pair(104, "Private/Experimental algorithm"),
                std::make_pair(105, "Private/Experimental algorithm"),
                std::make_pair(106, "Private/Experimental algorithm"),
                std::make_pair(107, "Private/Experimental algorithm"),
                std::make_pair(108, "Private/Experimental algorithm"),
                std::make_pair(109, "Private/Experimental algorithm"),
                std::make_pair(110, "Private/Experimental algorithm"),
};

const std::map <uint8_t, char> Public_Key_Algorithm_Short = {
    std::make_pair(1, 'R'),
    std::make_pair(2, 'R'),
    std::make_pair(3, 'R'),
    std::make_pair(16, 'g'),
    std::make_pair(17, 'D'),
};

const std::map <uint8_t, std::string> Public_Key_Type = {
    std::make_pair(5, "sec"),
    std::make_pair(6, "pub"),
    std::make_pair(7, "ssb"),
    std::make_pair(14, "sub"),
};

// Reasons for Revokation Tags
const std::map <uint8_t, std::string> Revoke = {
                std::make_pair(00, "No reason specified"),
                std::make_pair(01, "Key is superceded"),
                std::make_pair(02, "Key material has been compromised"),
                std::make_pair(03, "Key is no longer used"),
                std::make_pair(32, "User id information is no longer valid"),
};

// Signature Types
const std::map <uint8_t, std::string> Signature_Types = {
                std::make_pair(0, "Signature of a binary document."),
                std::make_pair(1, "Signature of a canonical text document"),
                std::make_pair(2, "Standalone signature"),
                std::make_pair(0x10, "Generic certification of a User ID and Public-Key packet"),
                std::make_pair(0x11, "Persona certification of a User ID and Public-Key packet"),
                std::make_pair(0x12, "Casual certification of a User ID and Public-Key packet"),
                std::make_pair(0x13, "Positive certification of a User ID and Public-Key packet"),
                std::make_pair(0x18, "Subkey Binding Signature"),
                std::make_pair(0x19, "Primary Key Binding Signature"),
                std::make_pair(0x1F, "Signature directly on a key"),
                std::make_pair(0x20, "Key revocation signature"),
                std::make_pair(0x28, "Subkey revocation signature"),
                std::make_pair(0x30, "Certification revocation signature"),
                std::make_pair(0x40, "Timestamp signature"),
                std::make_pair(0x50, "Third-Party Confirmation signature"),
};

// Subpacket Tags
const std::map <uint8_t, std::string> Subpacket_Tags = {
                std::make_pair(0, "Reserved"),
                std::make_pair(1, "Reserved"),
                std::make_pair(2, "Signature Creation Time"),
                std::make_pair(3, "Signature Expiration Time"),
                std::make_pair(4, "Exportable Certification"),
                std::make_pair(5, "Trust Signature"),
                std::make_pair(6, "Regular Expression"),
                std::make_pair(7, "Revocable"),
                std::make_pair(8, "Reserved"),
                std::make_pair(9, "Key Expiration Time"),
                std::make_pair(10, "Placeholder for Backward Compatibility"),            // No Format Defined
                std::make_pair(11, "Preferred Symmetric Algorithms"),
                std::make_pair(12, "Revocation Key"),
                std::make_pair(13, "Reserved"),
                std::make_pair(14, "Reserved"),
                std::make_pair(15, "Reserved"),
                std::make_pair(16, "Issuer"),
                std::make_pair(17, "Reserved"),
                std::make_pair(18, "Reserved"),
                std::make_pair(19, "Reserved"),
                std::make_pair(20, "Notation Data"),
                std::make_pair(21, "Preferred Hash Algorithms"),
                std::make_pair(22, "Preferred Compression Algorithms"),
                std::make_pair(23, "Key Server Preferences"),
                std::make_pair(24, "Preferred Key Server"),
                std::make_pair(25, "Primary User ID"),
                std::make_pair(26, "Policy URI"),
                std::make_pair(27, "Key Flags"),
                std::make_pair(28, "Signer's User ID"),
                std::make_pair(29, "Reason for Revocation"),
                std::make_pair(30, "Features"),
                std::make_pair(31, "Signature Target"),
                std::make_pair(32, "Embedded Signature"),
                std::make_pair(100, "Private/Experimental algorithm"),
                std::make_pair(101, "Private/Experimental algorithm"),
                std::make_pair(102, "Private/Experimental algorithm"),
                std::make_pair(103, "Private/Experimental algorithm"),
                std::make_pair(104, "Private/Experimental algorithm"),
                std::make_pair(105, "Private/Experimental algorithm"),
                std::make_pair(106, "Private/Experimental algorithm"),
                std::make_pair(107, "Private/Experimental algorithm"),
                std::make_pair(108, "Private/Experimental algorithm"),
                std::make_pair(109, "Private/Experimental algorithm"),
                std::make_pair(110, "Private/Experimental algorithm"),
};

// String to Key Specifiers
const std::map <uint8_t, std::string> String2Key_Specifiers = {
                std::make_pair(0, "Simple S2K"),
                std::make_pair(1, "Salted S2K"),
                std::make_pair(2, "Reserved value"),
                std::make_pair(3, "Iterated and Salted S2K"),
                std::make_pair(100, "Private/Experimental S2K"),
                std::make_pair(101, "Private/Experimental S2K"),
                std::make_pair(102, "Private/Experimental S2K"),
                std::make_pair(103, "Private/Experimental S2K"),
                std::make_pair(104, "Private/Experimental S2K"),
                std::make_pair(105, "Private/Experimental S2K"),
                std::make_pair(106, "Private/Experimental S2K"),
                std::make_pair(107, "Private/Experimental S2K"),
                std::make_pair(108, "Private/Experimental S2K"),
                std::make_pair(109, "Private/Experimental S2K"),
                std::make_pair(110, "Private/Experimental S2K"),
};

// Symmetric Key Algorithm Tags
const std::map <uint8_t, std::string> Symmetric_Algorithms = {
                std::make_pair(0, "PLAINTEXT"),
                std::make_pair(1, "IDEA"),
                std::make_pair(2, "TRIPLEDES"),
                std::make_pair(3, "CAST5"),
                std::make_pair(4, "BLOWFISH"),
                std::make_pair(5, "Reserved"),
                std::make_pair(6, "Reserved"),
                std::make_pair(7, "AES128"),
                std::make_pair(8, "AES192"),
                std::make_pair(9, "AES256"),
                std::make_pair(10, "TWOFISH256"),
                std::make_pair(11, "CAMELLIA128"),
                std::make_pair(12, "CAMELLIA192"),
                std::make_pair(13, "CAMELLIA256"),
                std::make_pair(100, "Private/Experimental algorithm"),
                std::make_pair(101, "Private/Experimental algorithm"),
                std::make_pair(102, "Private/Experimental algorithm"),
                std::make_pair(103, "Private/Experimental algorithm"),
                std::make_pair(104, "Private/Experimental algorithm"),
                std::make_pair(105, "Private/Experimental algorithm"),
                std::make_pair(106, "Private/Experimental algorithm"),
                std::make_pair(107, "Private/Experimental algorithm"),
                std::make_pair(108, "Private/Experimental algorithm"),
                std::make_pair(109, "Private/Experimental algorithm"),
                std::make_pair(110, "Private/Experimental algorithm"),
                std::make_pair(255, "Private/Experimental algorithm"),
};

// Reverse Symmetric_Algorithms
const std::map <std::string, uint8_t> Symmetric_Algorithms_Numbers = {
                std::make_pair("PLAINTEXT", 0),
                std::make_pair("IDEA", 1),
                std::make_pair("TRIPLEDES", 2),
                std::make_pair("CAST5", 3),
                std::make_pair("BLOWFISH", 4),
                std::make_pair("AES128", 7),
                std::make_pair("AES192", 8),
                std::make_pair("AES256", 9),
                std::make_pair("TWOFISH256", 10),
                std::make_pair("CAMELLIA128", 11),
                std::make_pair("CAMELLIA192", 12),
                std::make_pair("CAMELLIA256", 13),
};

// Block size of Symmetric Key Algorithms
const std::map <std::string, uint16_t> Symmetric_Algorithm_Block_Length = {
                std::make_pair("IDEA", 64),
                std::make_pair("TRIPLEDES", 64),
                std::make_pair("CAST5", 64),
                std::make_pair("BLOWFISH", 64),
                std::make_pair("AES128", 128),
                std::make_pair("AES192", 128),
                std::make_pair("AES256", 128),
                std::make_pair("Twofish256", 128),
                std::make_pair("CAMELLIA128", 128),
                std::make_pair("CAMELLIA192", 128),
                std::make_pair("CAMELLIA256", 128),
};

// Key size of Symmetric Key Algorithms
const std::map <std::string, uint16_t> Symmetric_Algorithm_Key_Length = {
                std::make_pair("IDEA", 128),
                std::make_pair("TRIPLEDES", 192),
                std::make_pair("CAST5", 128),
                std::make_pair("BLOWFISH", 128),
                std::make_pair("AES128", 128),
                std::make_pair("AES192", 192),
                std::make_pair("AES256", 256),
                std::make_pair("TWOFISH256", 256),
                std::make_pair("CAMELLIA128", 128),
                std::make_pair("CAMELLIA192", 192),
                std::make_pair("CAMELLIA256", 256),
};

// User Attribute Tags
const std::map <uint8_t, std::string> User_Attributes = {
                std::make_pair(1, "JPEG"),                                      // Only defined tag
                std::make_pair(100, "Reserved for private/experimental use"),
                std::make_pair(101, "Reserved for private/experimental use"),
                std::make_pair(102, "Reserved for private/experimental use"),
                std::make_pair(103, "Reserved for private/experimental use"),
                std::make_pair(104, "Reserved for private/experimental use"),
                std::make_pair(105, "Reserved for private/experimental use"),
                std::make_pair(106, "Reserved for private/experimental use"),
                std::make_pair(107, "Reserved for private/experimental use"),
                std::make_pair(108, "Reserved for private/experimental use"),
                std::make_pair(109, "Reserved for private/experimental use"),
                std::make_pair(110, "Reserved for private/experimental use"),
};
#endif
