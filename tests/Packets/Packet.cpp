#include <gtest/gtest.h>

#include "Packets/Packet.h"

TEST(Packet, is_key_packet){
    using namespace OpenPGP::Packet;

    EXPECT_FALSE(is_key_packet(RESERVED));
    EXPECT_FALSE(is_key_packet(PUBLIC_KEY_ENCRYPTED_SESSION_KEY));
    EXPECT_FALSE(is_key_packet(SIGNATURE));
    EXPECT_FALSE(is_key_packet(SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY));
    EXPECT_FALSE(is_key_packet(ONE_PASS_SIGNATURE));
    EXPECT_TRUE (is_key_packet(SECRET_KEY));
    EXPECT_TRUE (is_key_packet(PUBLIC_KEY));
    EXPECT_TRUE (is_key_packet(SECRET_SUBKEY));
    EXPECT_FALSE(is_key_packet(COMPRESSED_DATA));
    EXPECT_FALSE(is_key_packet(SYMMETRICALLY_ENCRYPTED_DATA));
    EXPECT_FALSE(is_key_packet(MARKER_PACKET));
    EXPECT_FALSE(is_key_packet(LITERAL_DATA));
    EXPECT_FALSE(is_key_packet(TRUST));
    EXPECT_FALSE(is_key_packet(USER_ID));
    EXPECT_TRUE (is_key_packet(PUBLIC_SUBKEY));
    EXPECT_FALSE(is_key_packet(USER_ATTRIBUTE));
    EXPECT_FALSE(is_key_packet(SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA));
    EXPECT_FALSE(is_key_packet(MODIFICATION_DETECTION_CODE));
}

TEST(Packet, is_primary_key){
    using namespace OpenPGP::Packet;

    EXPECT_FALSE(is_primary_key(RESERVED));
    EXPECT_FALSE(is_primary_key(PUBLIC_KEY_ENCRYPTED_SESSION_KEY));
    EXPECT_FALSE(is_primary_key(SIGNATURE));
    EXPECT_FALSE(is_primary_key(SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY));
    EXPECT_FALSE(is_primary_key(ONE_PASS_SIGNATURE));
    EXPECT_TRUE (is_primary_key(SECRET_KEY));
    EXPECT_TRUE (is_primary_key(PUBLIC_KEY));
    EXPECT_FALSE(is_primary_key(SECRET_SUBKEY));
    EXPECT_FALSE(is_primary_key(COMPRESSED_DATA));
    EXPECT_FALSE(is_primary_key(SYMMETRICALLY_ENCRYPTED_DATA));
    EXPECT_FALSE(is_primary_key(MARKER_PACKET));
    EXPECT_FALSE(is_primary_key(LITERAL_DATA));
    EXPECT_FALSE(is_primary_key(TRUST));
    EXPECT_FALSE(is_primary_key(USER_ID));
    EXPECT_FALSE(is_primary_key(PUBLIC_SUBKEY));
    EXPECT_FALSE(is_primary_key(USER_ATTRIBUTE));
    EXPECT_FALSE(is_primary_key(SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA));
    EXPECT_FALSE(is_primary_key(MODIFICATION_DETECTION_CODE));
}

TEST(Packet, is_subkey){
    using namespace OpenPGP::Packet;

    EXPECT_FALSE(is_subkey(RESERVED));
    EXPECT_FALSE(is_subkey(PUBLIC_KEY_ENCRYPTED_SESSION_KEY));
    EXPECT_FALSE(is_subkey(SIGNATURE));
    EXPECT_FALSE(is_subkey(SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY));
    EXPECT_FALSE(is_subkey(ONE_PASS_SIGNATURE));
    EXPECT_FALSE(is_subkey(SECRET_KEY));
    EXPECT_FALSE(is_subkey(PUBLIC_KEY));
    EXPECT_TRUE (is_subkey(SECRET_SUBKEY));
    EXPECT_FALSE(is_subkey(COMPRESSED_DATA));
    EXPECT_FALSE(is_subkey(SYMMETRICALLY_ENCRYPTED_DATA));
    EXPECT_FALSE(is_subkey(MARKER_PACKET));
    EXPECT_FALSE(is_subkey(LITERAL_DATA));
    EXPECT_FALSE(is_subkey(TRUST));
    EXPECT_FALSE(is_subkey(USER_ID));
    EXPECT_TRUE (is_subkey(PUBLIC_SUBKEY));
    EXPECT_FALSE(is_subkey(USER_ATTRIBUTE));
    EXPECT_FALSE(is_subkey(SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA));
    EXPECT_FALSE(is_subkey(MODIFICATION_DETECTION_CODE));
}

TEST(Packet, is_public){
    using namespace OpenPGP::Packet;

    EXPECT_FALSE(is_public(RESERVED));
    EXPECT_FALSE(is_public(PUBLIC_KEY_ENCRYPTED_SESSION_KEY));
    EXPECT_FALSE(is_public(SIGNATURE));
    EXPECT_FALSE(is_public(SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY));
    EXPECT_FALSE(is_public(ONE_PASS_SIGNATURE));
    EXPECT_FALSE(is_public(SECRET_KEY));
    EXPECT_TRUE (is_public(PUBLIC_KEY));
    EXPECT_FALSE(is_public(SECRET_SUBKEY));
    EXPECT_FALSE(is_public(COMPRESSED_DATA));
    EXPECT_FALSE(is_public(SYMMETRICALLY_ENCRYPTED_DATA));
    EXPECT_FALSE(is_public(MARKER_PACKET));
    EXPECT_FALSE(is_public(LITERAL_DATA));
    EXPECT_FALSE(is_public(TRUST));
    EXPECT_FALSE(is_public(USER_ID));
    EXPECT_TRUE (is_public(PUBLIC_SUBKEY));
    EXPECT_FALSE(is_public(USER_ATTRIBUTE));
    EXPECT_FALSE(is_public(SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA));
    EXPECT_FALSE(is_public(MODIFICATION_DETECTION_CODE));
}

TEST(Packet, is_secret){
    using namespace OpenPGP::Packet;

    EXPECT_FALSE(is_secret(RESERVED));
    EXPECT_FALSE(is_secret(PUBLIC_KEY_ENCRYPTED_SESSION_KEY));
    EXPECT_FALSE(is_secret(SIGNATURE));
    EXPECT_FALSE(is_secret(SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY));
    EXPECT_FALSE(is_secret(ONE_PASS_SIGNATURE));
    EXPECT_TRUE (is_secret(SECRET_KEY));
    EXPECT_FALSE(is_secret(PUBLIC_KEY));
    EXPECT_TRUE (is_secret(SECRET_SUBKEY));
    EXPECT_FALSE(is_secret(COMPRESSED_DATA));
    EXPECT_FALSE(is_secret(SYMMETRICALLY_ENCRYPTED_DATA));
    EXPECT_FALSE(is_secret(MARKER_PACKET));
    EXPECT_FALSE(is_secret(LITERAL_DATA));
    EXPECT_FALSE(is_secret(TRUST));
    EXPECT_FALSE(is_secret(USER_ID));
    EXPECT_FALSE(is_secret(PUBLIC_SUBKEY));
    EXPECT_FALSE(is_secret(USER_ATTRIBUTE));
    EXPECT_FALSE(is_secret(SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA));
    EXPECT_FALSE(is_secret(MODIFICATION_DETECTION_CODE));
}

TEST(Packet, is_user){
    using namespace OpenPGP::Packet;

    EXPECT_FALSE(is_user(RESERVED));
    EXPECT_FALSE(is_user(PUBLIC_KEY_ENCRYPTED_SESSION_KEY));
    EXPECT_FALSE(is_user(SIGNATURE));
    EXPECT_FALSE(is_user(SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY));
    EXPECT_FALSE(is_user(ONE_PASS_SIGNATURE));
    EXPECT_FALSE(is_user(SECRET_KEY));
    EXPECT_FALSE(is_user(PUBLIC_KEY));
    EXPECT_FALSE(is_user(SECRET_SUBKEY));
    EXPECT_FALSE(is_user(COMPRESSED_DATA));
    EXPECT_FALSE(is_user(SYMMETRICALLY_ENCRYPTED_DATA));
    EXPECT_FALSE(is_user(MARKER_PACKET));
    EXPECT_FALSE(is_user(LITERAL_DATA));
    EXPECT_FALSE(is_user(TRUST));
    EXPECT_TRUE (is_user(USER_ID));
    EXPECT_FALSE(is_user(PUBLIC_SUBKEY));
    EXPECT_TRUE (is_user(USER_ATTRIBUTE));
    EXPECT_FALSE(is_user(SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA));
    EXPECT_FALSE(is_user(MODIFICATION_DETECTION_CODE));
}

TEST(Packet, is_session_key){
    using namespace OpenPGP::Packet;

    EXPECT_FALSE(is_session_key(RESERVED));
    EXPECT_TRUE (is_session_key(PUBLIC_KEY_ENCRYPTED_SESSION_KEY));
    EXPECT_FALSE(is_session_key(SIGNATURE));
    EXPECT_TRUE (is_session_key(SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY));
    EXPECT_FALSE(is_session_key(ONE_PASS_SIGNATURE));
    EXPECT_FALSE(is_session_key(SECRET_KEY));
    EXPECT_FALSE(is_session_key(PUBLIC_KEY));
    EXPECT_FALSE(is_session_key(SECRET_SUBKEY));
    EXPECT_FALSE(is_session_key(COMPRESSED_DATA));
    EXPECT_FALSE(is_session_key(SYMMETRICALLY_ENCRYPTED_DATA));
    EXPECT_FALSE(is_session_key(MARKER_PACKET));
    EXPECT_FALSE(is_session_key(LITERAL_DATA));
    EXPECT_FALSE(is_session_key(TRUST));
    EXPECT_FALSE(is_session_key(USER_ID));
    EXPECT_FALSE(is_session_key(PUBLIC_SUBKEY));
    EXPECT_FALSE(is_session_key(USER_ATTRIBUTE));
    EXPECT_FALSE(is_session_key(SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA));
    EXPECT_FALSE(is_session_key(MODIFICATION_DETECTION_CODE));
}

TEST(Packet, is_sym_protected_data){
    using namespace OpenPGP::Packet;

    EXPECT_FALSE(is_sym_protected_data(RESERVED));
    EXPECT_FALSE(is_sym_protected_data(PUBLIC_KEY_ENCRYPTED_SESSION_KEY));
    EXPECT_FALSE(is_sym_protected_data(SIGNATURE));
    EXPECT_FALSE(is_sym_protected_data(SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY));
    EXPECT_FALSE(is_sym_protected_data(ONE_PASS_SIGNATURE));
    EXPECT_FALSE(is_sym_protected_data(SECRET_KEY));
    EXPECT_FALSE(is_sym_protected_data(PUBLIC_KEY));
    EXPECT_FALSE(is_sym_protected_data(SECRET_SUBKEY));
    EXPECT_FALSE(is_sym_protected_data(COMPRESSED_DATA));
    EXPECT_TRUE (is_sym_protected_data(SYMMETRICALLY_ENCRYPTED_DATA));
    EXPECT_FALSE(is_sym_protected_data(MARKER_PACKET));
    EXPECT_FALSE(is_sym_protected_data(LITERAL_DATA));
    EXPECT_FALSE(is_sym_protected_data(TRUST));
    EXPECT_FALSE(is_sym_protected_data(USER_ID));
    EXPECT_FALSE(is_sym_protected_data(PUBLIC_SUBKEY));
    EXPECT_FALSE(is_sym_protected_data(USER_ATTRIBUTE));
    EXPECT_TRUE (is_sym_protected_data(SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA));
    EXPECT_FALSE(is_sym_protected_data(MODIFICATION_DETECTION_CODE));
}

TEST(Packet, can_have_partial_length){
    using namespace OpenPGP::Packet;

    EXPECT_FALSE(can_have_partial_length(RESERVED));
    EXPECT_FALSE(can_have_partial_length(PUBLIC_KEY_ENCRYPTED_SESSION_KEY));
    EXPECT_FALSE(can_have_partial_length(SIGNATURE));
    EXPECT_FALSE(can_have_partial_length(SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY));
    EXPECT_FALSE(can_have_partial_length(ONE_PASS_SIGNATURE));
    EXPECT_FALSE(can_have_partial_length(SECRET_KEY));
    EXPECT_FALSE(can_have_partial_length(PUBLIC_KEY));
    EXPECT_FALSE(can_have_partial_length(SECRET_SUBKEY));
    EXPECT_TRUE (can_have_partial_length(COMPRESSED_DATA));
    EXPECT_TRUE (can_have_partial_length(SYMMETRICALLY_ENCRYPTED_DATA));
    EXPECT_FALSE(can_have_partial_length(MARKER_PACKET));
    EXPECT_TRUE (can_have_partial_length(LITERAL_DATA));
    EXPECT_FALSE(can_have_partial_length(TRUST));
    EXPECT_FALSE(can_have_partial_length(USER_ID));
    EXPECT_FALSE(can_have_partial_length(PUBLIC_SUBKEY));
    EXPECT_FALSE(can_have_partial_length(USER_ATTRIBUTE));
    EXPECT_TRUE (can_have_partial_length(SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA));
    EXPECT_FALSE(can_have_partial_length(MODIFICATION_DETECTION_CODE));
}

class FakeTag final : public OpenPGP::Packet::Tag {
    public:
        static std::string write_old_length(const uint8_t tag, const std::string & data, const OpenPGP::Packet::PartialBodyLength part, uint8_t octets = 0){
            return OpenPGP::Packet::Tag::write_old_length(tag, data, part, octets);
        }

        static std::string write_new_length(const uint8_t tag, const std::string & data, const OpenPGP::Packet::PartialBodyLength part, uint8_t octets = 0) {
            return OpenPGP::Packet::Tag::write_new_length(tag, data, part, octets);
        }

    private:
        void actual_read(const std::string &){}

    public:
        std::string show(const std::size_t, const std::size_t) const{
            return "";
        }

        std::string raw() const{
            return "";
        }

        OpenPGP::Packet::Tag::Ptr clone() const{
            return std::make_shared <FakeTag> (*this);
        }
};

static const uint8_t tag = OpenPGP::Packet::RESERVED;
static const uint8_t version = 3;
static const OpenPGP::Packet::HeaderFormat header_format = OpenPGP::Packet::HeaderFormat::NEW;
static const std::size_t size = 0;

static void TAG_FILL(FakeTag & faketag) {
    faketag.set_tag(tag);
    faketag.set_version(version);
    faketag.set_header_format(header_format);
    faketag.set_size(size);
}

#define TAG_EQ(faketag)                                                \
    EXPECT_EQ((faketag).get_tag(), tag);                               \
    EXPECT_EQ((faketag).get_version(), version);                       \
    EXPECT_EQ((faketag).get_header_format(), header_format);           \
    EXPECT_EQ((faketag).get_size(), size);

TEST(Tag, Constructor) {
    // Default constructor
    FakeTag faketag;

    EXPECT_EQ(faketag.raw(), "");
    EXPECT_NO_THROW(TAG_FILL(faketag));

    // Copy Constructor
    {
        FakeTag copy(faketag);
        TAG_EQ(copy);
    }

    // Move Constructor
    {
        FakeTag move(std::move(faketag));
        TAG_EQ(move);
    }
}

TEST(Tag, Assignment) {
    FakeTag faketag;
    EXPECT_NO_THROW(TAG_FILL(faketag));

    // Assignment
    {
        FakeTag copy;
        copy = faketag;
        TAG_EQ(copy);
    }

    // Move Assignment
    {
        FakeTag move;
        move = std::move(faketag);
        TAG_EQ(move);
    }
}

TEST(Tag, set_get) {
    FakeTag faketag;
    EXPECT_NO_THROW(TAG_FILL(faketag));
    TAG_EQ(faketag);
}

TEST(Tag, clone) {
    FakeTag faketag;
    EXPECT_NO_THROW(TAG_FILL(faketag));

    FakeTag::Ptr clone = faketag.clone();
    EXPECT_NE(&faketag, clone.get());
    TAG_EQ(*std::static_pointer_cast<FakeTag>(clone));
}

TEST(write_old_length, one_octet) {
    std::string data(255, '\x00');

    // pick a few sizes to check
    for(uint8_t const i : {0, 1, 2, 4, 8, 16, 32, 64, 128, 255}) {
        data.resize(i);

        {
            // write a 1 octet length
            const std::string out = FakeTag::write_old_length(tag, data, OpenPGP::Packet::PartialBodyLength::NOT_PARTIAL);

            // reduce copying when doing comparison
            EXPECT_EQ((uint8_t) out[0], 0x80 | (tag << 2) | 0x00);
            EXPECT_EQ((uint8_t) out[1], data.size());
            EXPECT_EQ(out.compare(2, i, data), 0);
        }

        {
            // force write a 1 octet length
            const std::string out = FakeTag::write_old_length(tag, data, OpenPGP::Packet::PartialBodyLength::NOT_PARTIAL, 1);

            // reduce copying when doing comparison
            EXPECT_EQ((uint8_t) out[0], 0x80 | (tag << 2) | 0x00);
            EXPECT_EQ((uint8_t) out[1], data.size());
            EXPECT_EQ(out.compare(2, i, data), 0);
        }
    }
}

TEST(write_old_length, two_octet) {
    {
        const std::string data(256, '\x00');

        // write a 2 octet length
        const std::string out = FakeTag::write_old_length(tag, data, OpenPGP::Packet::PartialBodyLength::NOT_PARTIAL);

        // reduce copying when doing comparison
        EXPECT_EQ((uint8_t) out[0], 0x80 | (tag << 2) | 0x01);
        EXPECT_EQ((uint8_t) out[1], (data.size() >> 8) & 0xff);
        EXPECT_EQ((uint8_t) out[2], (data.size() >> 0) & 0xff);
        EXPECT_EQ(out.compare(3, data.size(), data), 0);
    }

    {
        const std::string data(255, '\x00');

        // force write a 2 octet length
        const std::string out = FakeTag::write_old_length(tag, data, OpenPGP::Packet::PartialBodyLength::NOT_PARTIAL, 2);

        // reduce copying when doing comparison
        EXPECT_EQ((uint8_t) out[0], 0x80 | (tag << 2) | 0x01);
        EXPECT_EQ((uint8_t) out[1], 0);
        EXPECT_EQ((uint8_t) out[2], data.size());
        EXPECT_EQ(out.compare(3, data.size(), data), 0);
    }
}

TEST(write_old_length, four_octet) {
    {
        const std::string data(65536, '\x00');

        // write a 5-octet length
        const std::string out = FakeTag::write_old_length(tag, data, OpenPGP::Packet::PartialBodyLength::NOT_PARTIAL);

        // reduce copying when doing comparison
        EXPECT_EQ((uint8_t) out[0], 0x80 | (tag << 2) | 0x02);
        EXPECT_EQ((uint8_t) out[1], (data.size() >> 24) & 0xff);
        EXPECT_EQ((uint8_t) out[2], (data.size() >> 16) & 0xff);
        EXPECT_EQ((uint8_t) out[3], (data.size() >>  8) & 0xff);
        EXPECT_EQ((uint8_t) out[4], (data.size() >>  0) & 0xff);
        EXPECT_EQ(out.compare(5, data.size(), data), 0);
    }

    {
        const std::string data(255, '\x00');

        // force write a 5-octet length
        const std::string out = FakeTag::write_old_length(tag, data, OpenPGP::Packet::PartialBodyLength::NOT_PARTIAL, 5);

        // reduce copying when doing comparison
        EXPECT_EQ((uint8_t) out[0], 0x80 | (tag << 2) | 0x02);
        EXPECT_EQ((uint8_t) out[1], 0);
        EXPECT_EQ((uint8_t) out[2], 0);
        EXPECT_EQ((uint8_t) out[3], 0);
        EXPECT_EQ((uint8_t) out[4], data.size());
        EXPECT_EQ(out.compare(5, data.size(), data), 0);
    }
}

TEST(write_old_length, partial) {
    std::string data(255, '\x00');

    // write a partial length
    const std::string out = FakeTag::write_old_length(tag, data, OpenPGP::Packet::PartialBodyLength::PARTIAL);

    // reduce copying when doing comparison
    EXPECT_EQ((uint8_t) out[0], 0x80 | (tag << 2) | 0x03);
    EXPECT_EQ(out.compare(1, data.size(), data), 0);
}

TEST(write_new_length, one_octet) {
    std::string data(192, '\x00');

    // pick a few sizes to check
    for(uint8_t const i : {0, 1, 2, 4, 8, 16, 32, 64, 128, 191}) {
        data.resize(i);

        {
            // write a 1 octet length
            const std::string out = FakeTag::write_new_length(tag, data, OpenPGP::Packet::PartialBodyLength::NOT_PARTIAL);

            // reduce copying when doing comparison
            EXPECT_EQ((uint8_t) out[0], 0xc0 | tag);
            EXPECT_EQ((uint8_t) out[1], data.size());
            EXPECT_EQ(out.compare(2, i, data), 0);
        }

        {
            // force write a 1 octet length
            const std::string out = FakeTag::write_new_length(tag, data, OpenPGP::Packet::PartialBodyLength::NOT_PARTIAL, 1);

            // reduce copying when doing comparison
            EXPECT_EQ((uint8_t) out[0], 0xc0 | tag);
            EXPECT_EQ((uint8_t) out[1], data.size());
            EXPECT_EQ(out.compare(2, i, data), 0);
        }
    }
}

TEST(write_new_length, two_octet) {
    {
        const std::string data(192, '\x00');

        // write a 2-octet length
        const std::string out = FakeTag::write_new_length(tag, data, OpenPGP::Packet::PartialBodyLength::NOT_PARTIAL);

        // reduce copying when doing comparison
        EXPECT_EQ((uint8_t) out[0], 0xc0 | tag);
        EXPECT_EQ((((out[1] & 0xffU) - 192) << 8) + (out[2] & 0xffU) + 192U, data.size());
        EXPECT_EQ(out.compare(3, data.size(), data), 0);
    }

    {
        const std::string data(128, '\x00');

        // force write a 2-octet length
        const std::string out = FakeTag::write_new_length(tag, data, OpenPGP::Packet::PartialBodyLength::NOT_PARTIAL, 2);

        // reduce copying when doing comparison
        EXPECT_EQ((uint8_t) out[0], 0xc0 | tag);
        EXPECT_EQ((((out[1] & 0xffU) - 192) << 8) + (out[2] & 0xffU) + 192U, data.size());
        EXPECT_EQ(out.compare(3, data.size(), data), 0);
    }
}

TEST(write_new_length, four_octet) {
    {
        const std::string data(8384, '\x00');

        // write a 5-octet length
        const std::string out = FakeTag::write_new_length(tag, data, OpenPGP::Packet::PartialBodyLength::NOT_PARTIAL);

        // reduce copying when doing comparison
        EXPECT_EQ((uint8_t) out[0], 0xc0 | tag);
        EXPECT_EQ((uint8_t) out[1], 0xff);
        EXPECT_EQ((uint8_t) out[2], (data.size() >> 24) & 0xff);
        EXPECT_EQ((uint8_t) out[3], (data.size() >> 16) & 0xff);
        EXPECT_EQ((uint8_t) out[4], (data.size() >>  8) & 0xff);
        EXPECT_EQ((uint8_t) out[5], (data.size() >>  0) & 0xff);
        EXPECT_EQ(out.compare(6, data.size(), data), 0);
    }

    {
        const std::string data(128, '\x00');

        // force write a 5-octet length
        const std::string out = FakeTag::write_new_length(tag, data, OpenPGP::Packet::PartialBodyLength::NOT_PARTIAL, 5);

        // reduce copying when doing comparison
        EXPECT_EQ((uint8_t) out[0], 0xc0 | tag);
        EXPECT_EQ((uint8_t) out[1], 0xff);
        EXPECT_EQ((uint8_t) out[2], 0);
        EXPECT_EQ((uint8_t) out[3], 0);
        EXPECT_EQ((uint8_t) out[4], 0);
        EXPECT_EQ((uint8_t) out[5], data.size());
        EXPECT_EQ(out.compare(6, data.size(), data), 0);
    }
}

TEST(write_new_length, partial) {
    std::string data(513, '\x00');

    // write a partial length
    const std::string out = FakeTag::write_new_length(tag, data, OpenPGP::Packet::PartialBodyLength::PARTIAL);

    // move last octet to the next length header
    const char last = data.back();
    data.pop_back();

    // add last length header
    data += std::string(1, (uint8_t) (0xc0 | tag)) + std::string(1, '\x01') + std::string(1, last);

    // reduce copying when doing comparison
    EXPECT_EQ((uint8_t) out[0], 0xc0 | tag);
    EXPECT_EQ((uint8_t) out[1], 0xe0 + 9);
    EXPECT_EQ(out.compare(2, data.size(), data), 0);
}
