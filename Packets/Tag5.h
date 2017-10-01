/*
Tag5.h
Secret-Key Packet

Copyright (c) 2013 - 2017 Jason Lee @ calccrypto@gmail.com

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

#ifndef __TAG5__
#define __TAG5__

#include <string>

#include "../Misc/cfb.h"
#include "../Misc/mpi.h"
#include "../Misc/s2k.h"
#include "Tag6.h"

namespace OpenPGP {
    namespace Packet {

        // 5.5.1.3.  Secret-Key Packet (Tag 5)
        //
        //    A Secret-Key packet contains all the information that is found in a
        //    Public-Key packet, including the public-key material, but also
        //    includes the secret-key material after all the public-key fields.
        //
        // ...
        //
        // 5.5.3.  Secret-Key Packet Formats
        //
        //    The Secret-Key and Secret-Subkey packets contain all the data of the
        //    Public-Key and Public-Subkey packets, with additional algorithm-
        //    specific secret-key data appended, usually in encrypted form.
        //
        //    The packet contains:
        //
        //      - A Public-Key or Public-Subkey packet, as described above.
        //
        //      - One octet indicating string-to-key usage conventions.  Zero
        //        indicates that the secret-key data is not encrypted.  255 or 254
        //        indicates that a string-to-key specifier is being given.  Any
        //        other value is a symmetric-key encryption algorithm identifier.
        //
        //      - [Optional] If string-to-key usage octet was 255 or 254, a one-
        //        octet symmetric encryption algorithm.
        //
        //      - [Optional] If string-to-key usage octet was 255 or 254, a
        //        string-to-key specifier.  The length of the string-to-key
        //        specifier is implied by its type, as described above.
        //
        //      - [Optional] If secret data is encrypted (string-to-key usage octet
        //        not zero), an Initial Vector (IV) of the same length as the
        //        cipher's block size.
        //
        //      - Plain or encrypted multiprecision integers comprising the secret
        //        key data.  These algorithm-specific fields are as described
        //        below.
        //
        //      - If the string-to-key usage octet is zero or 255, then a two-octet
        //        checksum of the plaintext of the algorithm-specific portion (sum
        //        of all octets, mod 65536).  If the string-to-key usage octet was
        //        254, then a 20-octet SHA-1 hash of the plaintext of the
        //        algorithm-specific portion.  This checksum or hash is encrypted
        //        together with the algorithm-specific fields (if string-to-key
        //        usage octet is not zero).  Note that for all other values, a
        //        two-octet checksum is required.
        //
        //        Algorithm-Specific Fields for RSA secret keys:
        //
        //        - multiprecision integer (MPI) of RSA secret exponent d.
        //
        //        - MPI of RSA secret prime value p.
        //
        //        - MPI of RSA secret prime value q (p < q).
        //
        //        - MPI of u, the multiplicative inverse of p, mod q.
        //
        //        Algorithm-Specific Fields for DSA secret keys:
        //
        //        - MPI of DSA secret exponent x.
        //
        //        Algorithm-Specific Fields for ELGAMAL secret keys:
        //
        //        - MPI of ELGAMAL secret exponent x.
        //
        //    Secret MPI values can be encrypted using a passphrase.  If a string-
        //    to-key specifier is given, that describes the algorithm for
        //    converting the passphrase to a key, else a simple MD5 hash of the
        //    passphrase is used.  Implementations MUST use a string-to-key
        //    specifier; the simple hash is for backward compatibility and is
        //    deprecated, though implementations MAY continue to use existing
        //    private keys in the old format.  The cipher for encrypting the MPIs
        //    is specified in the Secret-Key packet.
        //
        //    Encryption/decryption of the secret data is done in CFB mode using
        //    the key created from the passphrase and the Initial Vector from the
        //    packet.  A different mode is used with V3 keys (which are only RSA)
        //    than with other key formats.  With V3 keys, the MPI bit count prefix
        //    (i.e., the first two octets) is not encrypted.  Only the MPI non-
        //    prefix data is encrypted.  Furthermore, the CFB state is
        //    resynchronized at the beginning of each new MPI value, so that the
        //    CFB block boundary is aligned with the start of the MPI data.
        //
        //    With V4 keys, a simpler method is used.  All secret MPI values are
        //    encrypted in CFB mode, including the MPI bitcount prefix.
        //
        //    The two-octet checksum that follows the algorithm-specific portion is
        //    the algebraic sum, mod 65536, of the plaintext of all the algorithm-
        //    specific octets (including MPI prefix and data).  With V3 keys, the
        //    checksum is stored in the clear.  With V4 keys, the checksum is
        //    encrypted like the algorithm-specific data.  This value is used to
        //    check that the passphrase was correct.  However, this checksum is
        //    deprecated; an implementation SHOULD NOT use it, but should rather
        //    use the SHA-1 hash denoted with a usage octet of 254.  The reason for
        //    this is that there are some attacks that involve undetectably
        //    modifying the secret key.

        class Tag5 : public Tag6 {
            protected:
                uint8_t s2k_con;
                uint8_t sym;
                S2K::S2K::Ptr s2k;
                std::string IV;
                std::string secret;

                void read_s2k(const std::string & data, std::string::size_type & pos);
                std::string show_private(const std::size_t indents = 0, const std::size_t indent_size = 4) const;

                Tag5(uint8_t tag);

            public:
                typedef std::shared_ptr <Packet::Tag5> Ptr;

                Tag5();
                Tag5(const Tag5 & copy);
                Tag5(const std::string & data);
                virtual ~Tag5();
                void read(const std::string & data);
                std::string show(const std::size_t indents = 0, const std::size_t indent_size = 4) const;
                std::string raw() const;

                uint8_t get_s2k_con() const;
                uint8_t get_sym() const;
                S2K::S2K::Ptr get_s2k() const;
                S2K::S2K::Ptr get_s2k_clone() const;
                std::string get_IV() const;
                std::string get_secret() const;

                Tag6 get_public_obj() const;            // extract public key from private key
                Tag6::Ptr get_public_ptr() const;       // extract public key from private key into a pointer

                void set_s2k_con(const uint8_t c);
                void set_sym(const uint8_t s);
                void set_s2k(const S2K::S2K::Ptr & s);
                void set_IV(const std::string & iv);
                void set_secret(const std::string & s); // directly set the secret keys

                // calculate the key used to encrypt the secret
                std::string calculate_key(const std::string & passphrase) const;

                // encrypt and set the secret keys
                const std::string & encrypt_secret_keys(const std::string & passphrase, const PKA::Values & keys);

                // decrypt the secret keys
                PKA::Values decrypt_secret_keys(const std::string & passphrase) const;

                Tag::Ptr clone() const;
                Tag5 & operator=(const Tag5 & copy);
        };
    }
}

#endif
