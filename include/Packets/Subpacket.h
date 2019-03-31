/*
Subpacket.h
Base class for OpenPGP Subpackets to inherit from

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

#ifndef __SUBPACKET__
#define __SUBPACKET__

#include <memory>
#include <string>

#include "common/HumanReadable.h"
#include "common/includes.h"
#include "common/Status.h"

namespace OpenPGP {
    namespace Subpacket {

        // 5.2.3.1. Signature Subpacket Specification
        //
        //    A Subpacket data set consists of zero or more Signature Subpackets.
        //    In Signature packets, the Subpacket data set is preceded by a two-
        //    octet scalar count of the length in octets of all the Subpackets. A
        //    pointer incremented by this number will skip over the Subpacket data
        //    set.
        //
        //    Each Subpacket consists of a Subpacket header and a body. The header
        //    consists of:
        //
        //      - the Subpacket length (1, 2, or 5 octets),
        //
        //      - the Subpacket type (1 octet),
        //
        //    and is followed by the Subpacket-specific data.
        //
        //    The length includes the type octet but not this length. Its format
        //    is similar to the "new" format packet header lengths, but cannot have
        //    Partial Body Lengths. That is:
        //
        //        if the 1st octet < 192, then
        //            lengthOfLength = 1
        //            SubpacketLen = 1st_octet
        //
        //        if the 1st octet >= 192 and < 255, then
        //            lengthOfLength = 2
        //            SubpacketLen = ((1st_octet - 192) << 8) + (2nd_octet) + 192
        //
        //        if the 1st octet = 255, then
        //            lengthOfLength = 5
        //            Subpacket length = [four-octet scalar starting at 2nd_octet]
        //
        //    ...
        //
        //    An implementation SHOULD ignore any Subpacket of a type that it does
        //    not recognize.
        //
        //    Bit 7 of the Subpacket type is the "critical" bit. If set, it
        //    denotes that the Subpacket is one that is critical for the evaluator
        //    of the signature to recognize. If a Subpacket is encountered that is
        //    marked critical but is unknown to the evaluating software, the
        //    evaluator SHOULD consider the signature to be in error.
        //
        //    An evaluator may "recognize" a Subpacket, but not implement it. The
        //    purpose of the critical bit is to allow the signer to tell an
        //    evaluator that it would prefer a new, unknown feature to generate an
        //    error than be ignored.
        //
        //    Implementations SHOULD implement the three preferred algorithm
        //    Subpackets (11, 21, and 22), as well as the "Reason for Revocation"
        //    Subpacket. Note, however, that if an implementation chooses not to
        //    implement some of the preferences, it is required to behave in a
        //    polite manner to respect the wishes of those users who do implement
        //    these preferences.

        class Sub {
            protected:
                static constexpr uint8_t NOT_CRITICAL = 0x00;
                static constexpr uint8_t CRITICAL     = 0x80;

                uint8_t critical;
                uint8_t type;
                std::size_t size; // only used for displaying. recalculated when writing

            public:
                static void read_subpacket(const std::string & data, std::string::size_type & pos, std::string::size_type & length);

            protected:
                virtual void actual_read(const std::string & data) = 0;

                virtual std::string show_critical() const;                       // prepend show_type with "critical"
                virtual std::string show_type    () const = 0;                   // defined by immediate child class
                virtual void        show_contents(HumanReadable & hr) const = 0; // defined by actual subpacket; should return at same level as entered

                std::string write_subpacket(const std::string & data) const;
                virtual Status actual_valid(const bool check_mpi) const;

                Sub(uint8_t type = 0, unsigned int size = 0, bool crit = false);

            public:
                typedef std::shared_ptr <Sub> Ptr;

                virtual ~Sub();
                void read(const std::string & data);
                std::string show(const std::size_t indents = 0, const std::size_t indent_size = 4) const;
                void show(HumanReadable & hr) const;
                virtual std::string raw() const;
                std::string write() const;
                Status valid(const bool check_mpi = false) const;

                // Accessors
                bool get_critical() const;
                uint8_t get_type() const;
                std::size_t get_size() const;

                // Modifiers
                void set_critical(const bool c);
                void set_type(const uint8_t t);
                void set_size(const std::size_t s);
        };
    }
}

#endif
