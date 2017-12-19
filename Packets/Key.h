/*
Key.h
Tag class for OpenPGP key packet types to inherit from

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

#ifndef __PACKET_KEY__
#define __PACKET_KEY__

#include "../Hashes/Hashes.h"
#include "../PKA/PKAs.h"
#include "../Misc/mpi.h"
#include "Packet.h"

namespace OpenPGP {
    namespace Packet {

        // For Tags 5, 6, 7, and 14
        // Key is equivalent to Tag6 (but don't substitute Key for Tag6)
        class Key : public Tag {
            protected:
                uint32_t time;
                uint8_t pka;
                PKA::Values mpi;

#ifdef GPG_COMPATIBLE
                std::string curve;
                std::string kdf_params;
#endif
                // version 3
                uint32_t expire;

                Key(uint8_t tag);

            public:
                typedef std::shared_ptr <Key> Ptr;

                Key();
                Key(const Key & copy);
                Key(const std::string & data);
                virtual ~Key();

                virtual void read(const std::string & data);
                virtual std::string show(const std::size_t indents = 0, const std::size_t indent_size = 4) const;
                virtual std::string raw() const;

                // read, show, and raw functions common to all keys tags
                // can't overload normal versions because the inherited versions are needed
                void read_common(const std::string & data, std::string::size_type & pos);
                std::string show_common(const std::size_t indents = 0, const std::size_t indent_size = 4) const;
                std::string raw_common() const;

                uint32_t get_time() const;
                uint32_t get_exp_time() const;
                uint8_t get_pka() const;
                PKA::Values get_mpi() const;

                void set_time(const uint32_t t);
                void set_pka(const uint8_t p);
                void set_mpi(const PKA::Values & m);

#ifdef GPG_COMPATIBLE
                std::string get_curve() const;
                void set_curve(const std::string c);
#endif

                std::string get_fingerprint() const;    // binary
                std::string get_keyid() const;          // binary

                virtual Packet::Tag::Ptr clone() const;

                Key & operator=(const Key & copy);
        };
    }
}

#endif