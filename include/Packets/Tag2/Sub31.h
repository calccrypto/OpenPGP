/*
Sub32.h
Signature Target

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

#ifndef __TAG2_SUB31__
#define __TAG2_SUB31__

#include "Hashes/Hashes.h"
#include "PKA/PKAs.h"
#include "Packets/Tag2/Subpacket.h"

namespace OpenPGP {
    namespace Subpacket {
        namespace Tag2 {

            // 5.2.3.25. Signature Target
            //
            //    (1 octet public-key algorithm, 1 octet hash algorithm, N octets hash)
            //
            //    This Subpacket identifies a specific target signature to which a
            //    signature refers. For revocation signatures, this Subpacket
            //    provides explicit designation of which signature is being revoked.
            //    For a third-party or timestamp signature, this designates what
            //    signature is signed. All arguments are an identifier of that target
            //    signature.
            //
            //    The N octets of hash data MUST be the size of the hash of the
            //    signature. For example, a target signature with a SHA-1 hash MUST
            //    have 20 octets of hash data.

            class Sub31 : public Sub {
                private:
                    uint8_t pka;
                    uint8_t hash_alg;
                    std::string hash;

                    void actual_read(const std::string & data);
                    void show_contents(HumanReadable & hr) const;
                    Status actual_valid(const bool check_mpi) const;

                public:
                    typedef std::shared_ptr <Sub31> Ptr;

                    Sub31();
                    Sub31(const std::string & data);
                    std::string raw() const;

                    uint8_t get_pka() const;
                    uint8_t get_hash_alg() const;
                    std::string get_hash() const;

                    void set_pka(const uint8_t p);
                    void set_hash_alg(const uint8_t h);
                    void set_hash(const std::string & h);

                    Sub::Ptr clone() const;
            };
        }
    }
}

#endif
