/*
s2k.h
String-to-Key Specifiers data structures as described in RFC 4880 sec 3.7

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

#ifndef __S2K__
#define __S2K__

#include <cstdint>
#include <map>
#include <memory>
#include <string>

#include "Encryptions/Encryptions.h"
#include "Hashes/Hashes.h"
#include "common/HumanReadable.h"
#include "common/Status.h"

namespace OpenPGP {
    namespace S2K {

        // 3.7. String-to-Key (S2K) Specifiers
        //
        //    String-to-key (S2K) specifiers are used to convert passphrase strings
        //    into symmetric-key encryption/decryption keys. They are used in two
        //    places, currently: to encrypt the secret part of private keys in the
        //    private keyring, and to convert passphrases to encryption keys for
        //    symmetrically encrypted messages.
        //
        // 3.7.1. String-to-Key (S2K) Specifier Types
        //
        //    There are three types of S2K specifiers currently supported, and
        //    some reserved values:
        //
        //        ID          S2K Type
        //        --          --------
        //        0           Simple S2K
        //        1           Salted S2K
        //        2           Reserved value
        //        3           Iterated and Salted S2K
        //        100 to 110  Private/Experimental S2K
        //
        //    These are described in Sections 3.7.1.1 - 3.7.1.3.

        namespace ID {
            constexpr uint8_t SIMPLE_S2K                        = 0;
            constexpr uint8_t SALTED_S2K                        = 1;
            constexpr uint8_t ITERATED_AND_SALTED_S2K           = 3;
        }

        const std::map <uint8_t, std::string> NAME = {
                    std::make_pair(ID::SIMPLE_S2K,              "Simple S2K"),
                    std::make_pair(ID::SALTED_S2K,              "Salted S2K"),
                    std::make_pair(2,                           "Reserved value"),
                    std::make_pair(ID::ITERATED_AND_SALTED_S2K, "Iterated and Salted S2K"),
                    std::make_pair(100,                         "Private/Experimental S2K"),
                    std::make_pair(101,                         "Private/Experimental S2K"),
                    std::make_pair(102,                         "Private/Experimental S2K"),
                    std::make_pair(103,                         "Private/Experimental S2K"),
                    std::make_pair(104,                         "Private/Experimental S2K"),
                    std::make_pair(105,                         "Private/Experimental S2K"),
                    std::make_pair(106,                         "Private/Experimental S2K"),
                    std::make_pair(107,                         "Private/Experimental S2K"),
                    std::make_pair(108,                         "Private/Experimental S2K"),
                    std::make_pair(109,                         "Private/Experimental S2K"),
                    std::make_pair(110,                         "Private/Experimental S2K"),
        };

        class S2K{
            protected:
                uint8_t type; // octet 0
                uint8_t hash; // octet 1

                std::string show_title() const;
                virtual void show_contents(HumanReadable & hr) const = 0;

                S2K(uint8_t uint8_t);

            public:
                typedef std::shared_ptr <S2K> Ptr;

                virtual ~S2K();
                        void read(const std::string & data);
                virtual void read(const std::string & data, std::string::size_type & pos);
                        void show(HumanReadable & hr) const;
                std::string show(const std::size_t indents = 0, const std::size_t indent_size = 4) const;
                virtual std::string raw() const = 0;
                std::string write() const;
                virtual std::string run(const std::string & pass, const std::size_t sym_key_len) const = 0;

                uint8_t get_type() const;
                uint8_t get_hash() const;

                void set_type(const uint8_t t);
                void set_hash(const uint8_t h);

                virtual Status valid() const = 0;

                virtual Ptr clone() const = 0;
        };

        // 3.7.1.1. Simple S2K
        //
        //    This directly hashes the string to produce the key data. See below
        //    for how this hashing is done.
        //
        //        Octet 0: 0x00
        //        Octet 1: hash algorithm
        //
        //    Simple S2K hashes the passphrase to produce the session key. The
        //    manner in which this is done depends on the size of the session key
        //    (which will depend on the cipher used) and the size of the hash
        //    algorithm’s output. If the hash size is greater than the session key
        //    size, the high-order (leftmost) octets of the hash are used as the
        //    key.
        //
        //    If the hash size is less than the key size, multiple instances of the
        //    hash context are created -- enough to produce the required key data.
        //    These instances are preloaded with 0, 1, 2, ... octets of zeros (that
        //    is to say, the first instance has no preloading, the second gets
        //    preloaded with 1 octet of zero, the third is preloaded with two
        //    octets of zeros, and so forth).
        //
        //    As the data is hashed, it is given independently to each hash
        //    context. Since the contexts have been initialized differently, they
        //    will each produce different hash output. Once the passphrase is
        //    hashed, the output data from the multiple hashes is concatenated,
        //    first hash leftmost, to produce the key data, with any excess octets
        //    on the right discarded.

        class S2K0: public S2K {
            protected:
                virtual void show_contents(HumanReadable & hr) const;

                S2K0(uint8_t t);

            public:
                typedef std::shared_ptr <S2K0> Ptr;

                S2K0();
                S2K0(const std::string & data);
                virtual ~S2K0();
                virtual void read(const std::string & data, std::string::size_type & pos);
                virtual std::string raw() const;
                virtual std::string run(const std::string & pass, const std::size_t sym_key_len) const;

                Status valid() const;

                S2K::Ptr clone() const;
        };

        // 3.7.1.2. Salted S2K
        //    This includes a "salt" value in the S2K specifier -- some arbitrary
        //    data -- that gets hashed along with the passphrase string, to help
        //    prevent dictionary attacks.
        //
        //        Octet 0: 0x01
        //        Octet 1: hash algorithm
        //        Octets 2-9: 8-octet salt value
        //
        //    Salted S2K is exactly like Simple S2K, except that the input to the
        //    hash function(s) consists of the 8 octets of salt from the S2K
        //    specifier, followed by the passphrase.

        class S2K1 : public S2K0 {
            protected:
                std::string salt;   // 8 octets

                virtual void show_contents(HumanReadable & hr) const;

                S2K1(uint8_t t);

            public:
                typedef std::shared_ptr <S2K1> Ptr;

                S2K1();
                S2K1(const std::string & data);
                virtual ~S2K1();
                virtual void read(const std::string & data, std::string::size_type & pos);
                virtual std::string raw() const;
                virtual std::string run(const std::string & pass, const std::size_t sym_key_len) const;

                std::string get_salt() const;

                void set_salt(const std::string & s);

                Status valid() const;

                S2K::Ptr clone() const;
        };

        // 3.7.1.3. Iterated and Salted S2K
        //
        //    This includes both a salt and an octet count. The salt is combined
        //    with the passphrase and the resulting value is hashed repeatedly.
        //    This further increases the amount of work an attacker must do to try
        //    dictionary attacks.
        //
        //        Octet 0: 0x03
        //        Octet 1: hash algorithm
        //        Octets 2-9: 8-octet salt value
        //        Octet 10: count, a one-octet, coded value
        //
        //    The count is coded into a one-octet number using the following
        //    formula:
        //
        //        #define EXPBIAS 6
        //            count = ((Int32)16 + (c & 15)) << ((c >> 4) + EXPBIAS);
        //
        //    The above formula is in C, where "Int32" is a type for a 32-bit
        //    integer, and the variable "c" is the coded count, Octet 10.
        //    Iterated-Salted S2K hashes the passphrase and salt data multiple
        //    times. The total number of octets to be hashed is specified in the
        //    encoded count in the S2K specifier. Note that the resulting count
        //    value is an octet count of how many octets will be hashed, not an
        //    iteration count.
        //
        //    Initially, one or more hash contexts are set up as with the other S2K
        //    algorithms, depending on how many octets of key data are needed.
        //    Then the salt, followed by the passphrase data, is repeatedly hashed
        //    until the number of octets specified by the octet count has been
        //    hashed. The one exception is that if the octet count is less than
        //    the size of the salt plus passphrase, the full salt plus passphrase
        //    will be hashed even though that is greater than the octet count.
        //    After the hashing is done, the data is unloaded from the hash
        //    context(s) as with the other S2K algorithms.

         class S2K3 : public S2K1 {
            private:
                static const uint32_t EXPBIAS = 6;
                static uint32_t coded_count(const uint8_t c);

            private:
                uint8_t count;

                void show_contents(HumanReadable & hr) const;

            public:
                typedef std::shared_ptr <S2K3> Ptr;

                S2K3();
                S2K3(const std::string & data);
                ~S2K3();
                void read(const std::string & data, std::string::size_type & pos);
                std::string raw() const;
                std::string run(const std::string & pass, const std::size_t sym_key_len) const;

                uint8_t get_count() const;

                void set_count(const uint8_t c);

                Status valid() const;

                S2K::Ptr clone() const;
        };

        // 3.7.2. String-to-Key Usage
        //
        //    Implementations SHOULD use salted or iterated-and-salted S2K
        //    specifiers, as simple S2K specifiers are more vulnerable to
        //    dictionary attacks.
    }
}

#endif
