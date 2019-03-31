#include <gtest/gtest.h>

#include "Packets/Packet.h"

TEST(Packet, is_key_packet) {
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

TEST(Packet, is_primary_key) {
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

TEST(Packet, is_subkey) {
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

TEST(Packet, is_public) {
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

TEST(Packet, is_secret) {
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

TEST(Packet, is_user) {
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

TEST(Packet, is_session_key) {
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

TEST(Packet, is_sym_protected_data) {
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

TEST(Packet, can_have_partial_length) {
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
    private:
        void actual_read(const std::string &, std::string::size_type &, const std::string::size_type &) {}

        void show_contents(HumanReadable &) const {}

        std::string actual_raw() const {
            return "";
        }

        OpenPGP::Status actual_valid(const bool) const {
            return OpenPGP::Status::INVALID;
        }

    public:
        OpenPGP::Packet::Tag::Ptr clone() const {
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

#define TAG_EQ(faketag)                                         \
    EXPECT_EQ((faketag).get_tag(), tag);                        \
    EXPECT_EQ((faketag).get_version(), version);                \
    EXPECT_EQ((faketag).get_header_format(), header_format);    \
    EXPECT_EQ((faketag).get_size(), size);                      \
    EXPECT_EQ((faketag).valid(true), OpenPGP::Status::INVALID);

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
