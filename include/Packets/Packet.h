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
#include <string>

#include "Packets/PartialBodyLengthEnums.h"
#include "common/HumanReadable.h"
#include "common/Status.h"
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

        constexpr uint8_t RESERVED                                 = 0;
        constexpr uint8_t PUBLIC_KEY_ENCRYPTED_SESSION_KEY         = 1;
        constexpr uint8_t SIGNATURE                                = 2;
        constexpr uint8_t SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY      = 3;
        constexpr uint8_t ONE_PASS_SIGNATURE                       = 4;
        constexpr uint8_t SECRET_KEY                               = 5;
        constexpr uint8_t PUBLIC_KEY                               = 6;
        constexpr uint8_t SECRET_SUBKEY                            = 7;
        constexpr uint8_t COMPRESSED_DATA                          = 8;
        constexpr uint8_t SYMMETRICALLY_ENCRYPTED_DATA             = 9;
        constexpr uint8_t MARKER_PACKET                            = 10;
        constexpr uint8_t LITERAL_DATA                             = 11;
        constexpr uint8_t TRUST                                    = 12;
        constexpr uint8_t USER_ID                                  = 13;
        constexpr uint8_t PUBLIC_SUBKEY                            = 14;
        constexpr uint8_t USER_ATTRIBUTE                           = 17;
        constexpr uint8_t SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA   = 18;
        constexpr uint8_t MODIFICATION_DETECTION_CODE              = 19;
        constexpr uint8_t UNKNOWN                                  = 255; // not part of standard

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
        bool can_have_partial_length (const uint8_t t);

        // Packet Header Format
        enum class HeaderFormat : bool {
            OLD,
            NEW
        };

        // Tag class for all packet types
        class Tag {
            protected:
                uint8_t tag;                  // RFC 4880 sec 4.3
                uint8_t version;
                HeaderFormat header_format;
                std::size_t size;             // This value is only correct when the Tag was generated with the read() function

                // the actual implementations of the public functions
                virtual void actual_read(const std::string & data, std::string::size_type & pos, const std::string::size_type & length) = 0;
                virtual std::string show_title() const;
                virtual void show_contents(HumanReadable & hr) const = 0;
                virtual std::string actual_raw() const = 0;
                virtual std::string actual_write() const;
                virtual Status actual_valid(const bool check_mpi) const = 0;

                Tag(const uint8_t t);
                Tag(const uint8_t t, const uint8_t ver);

            public:
                typedef std::shared_ptr <Tag> Ptr;

                Tag();
                virtual ~Tag();
                void read(const std::string & data, std::string::size_type & pos, const std::string::size_type & length, const bool check_end = true);
                void read(const std::string & data, const bool check_end = true);
                void show(HumanReadable & hr) const;
                std::string show(const std::size_t indents = 0, const std::size_t indent_size = 4) const;
                std::string raw(Status * status = nullptr, const bool check_mpi = false) const;
                virtual std::string write(Status * status = nullptr, const bool check_mpi = false) const;
                Status valid(const bool check_mpi = false) const;

                // Accessors
                uint8_t get_tag() const;
                HeaderFormat get_header_format() const;
                uint8_t get_version() const;
                std::size_t get_size() const;

                // Modifiers
                void set_tag(const uint8_t t);
                void set_header_format(const HeaderFormat hf);
                void set_version(const uint8_t v);
                void set_size(const std::size_t s);

                virtual Ptr clone() const = 0;
        };

        // These two functions override the operators only with Tag::Ptr.
        // They don't work with Ptr of types different than Tag (Tag1, Tag2, etc.)
        inline bool operator==(const Tag::Ptr & lhs, const Tag::Ptr & rhs){
            return (lhs -> get_tag() == rhs -> get_tag()) &&
                   (lhs -> raw()     == rhs -> raw());
        }

        inline bool operator!=(const Tag::Ptr & lhs, const Tag::Ptr & rhs){
            return !(lhs == rhs);
        }
    }
}

#endif
