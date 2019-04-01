#include <gtest/gtest.h>

#include "Packets/Tag2/Sub29.h"

static const uint8_t code = OpenPGP::Subpacket::Tag2::Revoke::NO_REASON_SPECIFIED;
static const std::string reason = "";

static void TAG2_SUB29_FILL(OpenPGP::Subpacket::Tag2::Sub29 & sub29) {
    sub29.set_code(code);
    sub29.set_reason(reason);
}

#define TAG2_SUB29_EQ(sub29)                    \
    EXPECT_EQ((sub29).get_code(), code);        \
    EXPECT_EQ((sub29).get_reason(), reason);    \
    EXPECT_EQ((sub29).valid(true), OpenPGP::Status::SUCCESS);

TEST(Tag2Sub29, Constructor) {
    // Default constructor
    OpenPGP::Subpacket::Tag2::Sub29 sub29;

    EXPECT_EQ(sub29.raw(), std::string(1, '\x00'));
    EXPECT_NO_THROW(TAG2_SUB29_FILL(sub29));

    // String Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub29 str(sub29.raw());
        TAG2_SUB29_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub29 copy(sub29);
        TAG2_SUB29_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub29 move(std::move(sub29));
        TAG2_SUB29_EQ(move);
    }
}

TEST(Tag2Sub29, Assignment) {
    OpenPGP::Subpacket::Tag2::Sub29 sub29;
    EXPECT_NO_THROW(TAG2_SUB29_FILL(sub29));

    // Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub29 copy;
        copy = sub29;
        TAG2_SUB29_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub29 move;
        move = std::move(sub29);
        TAG2_SUB29_EQ(move);
    }
}

TEST(Tag2Sub29, read_write) {
    const std::string raw = std::string(1, code) + reason;

    OpenPGP::Subpacket::Tag2::Sub29 sub29(raw);
    TAG2_SUB29_EQ(sub29);
    EXPECT_EQ(sub29.raw(), raw);
}

TEST(Tag2Sub29, show) {
    OpenPGP::Subpacket::Tag2::Sub29 sub29;
    EXPECT_NO_THROW(TAG2_SUB29_FILL(sub29));
    EXPECT_NO_THROW(sub29.show());
}

TEST(Tag2Sub29, set_get) {
    OpenPGP::Subpacket::Tag2::Sub29 sub29;
    TAG2_SUB29_FILL(sub29);
    TAG2_SUB29_EQ(sub29);
}

TEST(Tag2Sub29, clone) {
    OpenPGP::Subpacket::Tag2::Sub29 sub29;
    EXPECT_NO_THROW(TAG2_SUB29_FILL(sub29));

    OpenPGP::Subpacket::Sub::Ptr clone = sub29.clone();
    EXPECT_NE(&sub29, clone.get());
    TAG2_SUB29_EQ(*std::static_pointer_cast<OpenPGP::Subpacket::Tag2::Sub29>(clone));
}
