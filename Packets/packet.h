/*
packet.h
Base class for OpenPGP packet types to inherit from

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

#ifndef __PACKET__
#define __PACKET__

#include <map>
#include <memory>
#include <stdexcept>
#include <string>

#include "../common/includes.h"

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

class Packet{
    public:
        static const uint8_t RESERVED;
        static const uint8_t PUBLIC_KEY_ENCRYPTED_SESSION_KEY;
        static const uint8_t SIGNATURE;
        static const uint8_t SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY;
        static const uint8_t ONE_PASS_SIGNATURE;
        static const uint8_t SECRET_KEY;
        static const uint8_t PUBLIC_KEY;
        static const uint8_t SECRET_SUBKEY;
        static const uint8_t COMPRESSED_DATA;
        static const uint8_t SYMMETRICALLY_ENCRYPTED_DATA;
        static const uint8_t MARKER_PACKET;
        static const uint8_t LITERAL_DATA;
        static const uint8_t TRUST;
        static const uint8_t USER_ID;
        static const uint8_t PUBLIC_SUBKEY;
        static const uint8_t USER_ATTRIBUTE;
        static const uint8_t SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA;
        static const uint8_t MODIFICATION_DETECTION_CODE;
        static const uint8_t UNKNOWN;   // not part of standard

        static const std::map <uint8_t, std::string> NAME;

        // check packets for attributes
        static bool is_key_packet           (const uint8_t t);
        static bool is_primary_key          (const uint8_t t);
        static bool is_subkey               (const uint8_t t);
        static bool is_public               (const uint8_t t);
        static bool is_secret               (const uint8_t t);
        static bool is_user                 (const uint8_t t);
        static bool is_session_key          (const uint8_t t);
        static bool is_sym_protected_data   (const uint8_t t);

	public:
		enum Format{
			DEFAULT,
			OLD,
			NEW,
		};

    protected:
        uint8_t tag;        // RFC 4880 sec 4.3
        uint8_t version;
        bool format;        // OLD (false) or NEW (true); defaults to NEW
        std::size_t size;   // This value is only correct when the packet was generated with the read() function
        uint8_t partial;    // 0-3; 0 = not partial, 1 = partial begin, 2 = partial continue, 3 = partial end

        // returns packet data with old format packet length
        std::string write_old_length(const std::string & data) const;

        // returns packet data with new format packet length
        std::string write_new_length(const std::string & data) const;

        // returns first line of show functions (no tab or newline)
        virtual std::string show_title() const; // virtual to allow for overriding for special cases

        Packet(const uint8_t t);
        Packet(const uint8_t t, const uint8_t ver);
        Packet(const Packet & copy);

    public:
        typedef std::shared_ptr <Packet> Ptr;

        Packet();
        virtual ~Packet();
        virtual void read(const std::string & data) = 0;
        virtual std::string show(const uint8_t indents = 0, const uint8_t indent_size = 4) const = 0;
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

        virtual Ptr clone() const = 0;

        Packet & operator=(const Packet & copy);
};

#endif
