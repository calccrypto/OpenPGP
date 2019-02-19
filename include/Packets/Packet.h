/*
Packet.h
Tag class for OpenPGP packet types to inherit from

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

#ifndef __PACKET__
#define __PACKET__

#include <map>
#include <memory>
#include <stdexcept>
#include <string>

#include "common/includes.h"

namespace OpenPGP {
    namespace Packet {

        // 4.3. Packet Tags
        //
        //   The packet tag denotes what type of packet the body holds. Note that
        //   old format headers can only have tags less than 16, whereas new
        //   format headers can have tags as great as 63. The defined tags (in
        //   decimal) are as follows:
        //
        //       0        -- Reserved - a packet tag MUST NOT have this value
        //       1        -- Public-Key Encrypted Session Key Packet
        //       2        -- Signature Packet
        //       3        -- Symmetric-Key Encrypted Session Key Packet
        //       4        -- One-Pass Signature Packet
        //       5        -- Secret-Key Packet
        //       6        -- Public-Key Packet
        //       7        -- Secret-Subkey Packet
        //       8        -- Compressed Data Packet
        //       9        -- Symmetrically Encrypted Data Packet
        //       10       -- Marker Packet
        //       11       -- Literal Data Packet
        //       12       -- Trust Packet
        //       13       -- User ID Packet
        //       14       -- Public-Subkey Packet
        //       17       -- User Attribute Packet
        //       18       -- Sym. Encrypted and Integrity Protected Data Packet
        //       19       -- Modification Detection Code Packet
        //       60 to 63 -- Private or Experimental Values

        const uint8_t RESERVED                                     = 0;
        const uint8_t PUBLIC_KEY_ENCRYPTED_SESSION_KEY             = 1;
        const uint8_t SIGNATURE                                    = 2;
        const uint8_t SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY          = 3;
        const uint8_t ONE_PASS_SIGNATURE                           = 4;
        const uint8_t SECRET_KEY                                   = 5;
        const uint8_t PUBLIC_KEY                                   = 6;
        const uint8_t SECRET_SUBKEY                                = 7;
        const uint8_t COMPRESSED_DATA                              = 8;
        const uint8_t SYMMETRICALLY_ENCRYPTED_DATA                 = 9;
        const uint8_t MARKER_PACKET                                = 10;
        const uint8_t LITERAL_DATA                                 = 11;
        const uint8_t TRUST                                        = 12;
        const uint8_t USER_ID                                      = 13;
        const uint8_t PUBLIC_SUBKEY                                = 14;
        const uint8_t USER_ATTRIBUTE                               = 17;
        const uint8_t SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA       = 18;
        const uint8_t MODIFICATION_DETECTION_CODE                  = 19;
        const uint8_t UNKNOWN                                      = 255; // not part of standard

        const std::map <uint8_t, std::string> NAME = {
            std::make_pair(RESERVED,                               "Reserved - a packet tag MUST NOT have this value"),
            std::make_pair(PUBLIC_KEY_ENCRYPTED_SESSION_KEY,       "Public-Key Encrypted Session Key"),
            std::make_pair(SIGNATURE,                              "Signature"),
            std::make_pair(SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY,    "Symmetric-Key Encrypted Session Key"),
            std::make_pair(ONE_PASS_SIGNATURE,                     "One-Pass Signature"),
            std::make_pair(SECRET_KEY,                             "Secret-Key"),
            std::make_pair(PUBLIC_KEY,                             "Public-Key"),
            std::make_pair(SECRET_SUBKEY,                          "Secret-Subkey"),
            std::make_pair(COMPRESSED_DATA,                        "Compressed Data"),
            std::make_pair(SYMMETRICALLY_ENCRYPTED_DATA,           "Symmetrically (Conventional) Encrypted Data"),
            std::make_pair(MARKER_PACKET,                          "Marker Packet (Obsolete Literal Packet)"),
            std::make_pair(LITERAL_DATA,                           "Literal Data"),
            std::make_pair(TRUST,                                  "(Keyring) Trust"),
            std::make_pair(USER_ID,                                "User ID"),
            std::make_pair(PUBLIC_SUBKEY,                          "Public-Subkey (Obsolete Comment Packet)"),
            std::make_pair(USER_ATTRIBUTE,                         "User Attribute"),
            std::make_pair(SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA, "Sym. Encrypted Integrity Protected Data"),
            std::make_pair(MODIFICATION_DETECTION_CODE,            "Modification Detection Code"),
            std::make_pair(60,                                     "Private or Experimental Values"),
            std::make_pair(61,                                     "Private or Experimental Values"),
            std::make_pair(62,                                     "Private or Experimental Values"),
            std::make_pair(63,                                     "Private or Experimental Values"),
        };

        // utility functions to check packets for attributes
        bool is_key_packet           (const uint8_t t);
        bool is_primary_key          (const uint8_t t);
        bool is_subkey               (const uint8_t t);
        bool is_public               (const uint8_t t);
        bool is_secret               (const uint8_t t);
        bool is_user                 (const uint8_t t);
        bool is_session_key          (const uint8_t t);
        bool is_sym_protected_data   (const uint8_t t);

        // Tag class for all packet types
        class Tag {
            public:
                enum Format {
                    DEFAULT,
                    OLD,
                    NEW,
                };

                // 4.2.1.  Old Format Packet Lengths
                //
                //     The meaning of the length-type in old format packets is:
                //
                //     ...
                //
                //
                //     3 - The packet is of indeterminate length.  The header is 1 octet
                //         long, and the implementation must determine how long the packet
                //         is.  If the packet is in a file, this means that the packet
                //         extends until the end of the file.  In general, an implementation
                //         SHOULD NOT use indeterminate-length packets except where the end
                //         of the data will be clear from the context, and even then it is
                //         better to use a definite length, or a new format header.  The new
                //         format headers described below have a mechanism for precisely
                //         encoding data of indeterminate length.

                // 4.2.2.4.  Partial Body Lengths
                //
                //     A Partial Body Length header is one octet long and encodes the length
                //     of only part of the data packet.  This length is a power of 2, from 1
                //     to 1,073,741,824 (2 to the 30th power).  It is recognized by its one
                //     octet value that is greater than or equal to 224, and less than 255.
                //     The Partial Body Length is equal to:
                //
                //         partialBodyLen = 1 << (1st_octet & 0x1F);
                //
                //     Each Partial Body Length header is followed by a portion of the
                //     packet body data.  The Partial Body Length header specifies this
                //     portion's length.  Another length header (one octet, two-octet,
                //     five-octet, or partial) follows that portion.  The last length header
                //     in the packet MUST NOT be a Partial Body Length header.  Partial Body
                //     Length headers may only be used for the non-final parts of the
                //     packet.
                //
                //     Note also that the last Body Length header can be a zero-length
                //     header.
                //
                //     An implementation MAY use Partial Body Lengths for data packets, be
                //     they literal, compressed, or encrypted.  The first partial length
                //     MUST be at least 512 octets long.  Partial Body Lengths MUST NOT be
                //     used for any other packet types.

                static const uint8_t NOT_PARTIAL               = 0;
                static const uint8_t PARTIAL_START             = 1;
                static const uint8_t PARTIAL_CONTINUE          = 2;
                static const uint8_t PARTIAL_END               = 3;

                static const uint8_t PARTIAL_BODY_LENGTH_START = 224;
                static const uint8_t PARTIAL_BODY_LENGTH_END   = 254;

            protected:
                uint8_t tag;        // RFC 4880 sec 4.3
                uint8_t version;
                bool format;        // OLD (false) or NEW (true); defaults to NEW
                std::size_t size;   // This value is only correct when the Tag was generated with the read() function
                uint8_t partial;    // 0-3; 0 = not partial, 1 = partial begin, 2 = partial continue, 3 = partial end

                // returns Tag data with old format Tag length
                std::string write_old_length(const std::string & data) const;

                // returns Tag data with new format Tag length
                std::string write_new_length(const std::string & data) const;

                // returns first line of show functions (no tab or newline)
                virtual std::string show_title() const; // virtual to allow for overriding for special cases

                Tag(const uint8_t t);
                Tag(const uint8_t t, const uint8_t ver);
                Tag(const Tag & copy);

            public:
                typedef std::shared_ptr <Tag> Ptr;

                Tag();
                virtual ~Tag();
                virtual void read(const std::string & data) = 0;
                virtual std::string show(const std::size_t indents = 0, const std::size_t indent_size = 4) const = 0;
                virtual std::string raw() const = 0;
                std::string write(const Format header = DEFAULT) const;

                // Accessors
                uint8_t get_tag() const;
                bool get_format() const;
                uint8_t get_version() const;
                std::size_t get_size() const;
                uint8_t get_partial() const;

                // Modifiers
                void set_tag(const uint8_t t);
                void set_format(const bool f);
                void set_version(const uint8_t v);
                void set_size(const std::size_t s);
                void set_partial(const uint8_t p);

                bool valid() const;

                virtual Ptr clone() const = 0;

                Tag & operator=(const Tag & copy);
            };

        // These two functions override the operators only with Tag::Ptr.
        // They don't work with Ptr of types different than Tag (Tag1, Tag2, etc.)
        inline bool operator==(Tag::Ptr lhs, Tag::Ptr rhs){
            return lhs -> raw() == rhs -> raw();
        }

        inline bool operator!=(Tag::Ptr lhs, Tag::Ptr rhs){
            return !(lhs == rhs);
        }
    }
}

#endif
