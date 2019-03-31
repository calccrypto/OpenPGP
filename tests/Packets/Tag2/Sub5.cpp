#include <gtest/gtest.h>

#include "Packets/Tag2/Sub5.h"

static const uint8_t level = 0;
static const uint8_t amount = 0;

static void TAG2_SUB5_FILL(OpenPGP::Subpacket::Tag2::Sub5 & sub5) {
    sub5.set_level(level);
    sub5.set_amount(amount);
}

#define TAG2_SUB5_EQ(sub5)                      \
    EXPECT_EQ((sub5).get_level(), level);       \
    EXPECT_EQ((sub5).get_amount(), amount);     \
    EXPECT_EQ((sub5).valid(true), OpenPGP::Status::SUCCESS);

TEST(Tag2Sub5, Constructor) {
    // Default constructor
    OpenPGP::Subpacket::Tag2::Sub5 sub5;

    EXPECT_EQ(sub5.raw(), std::string(1, level) + std::string(1, amount));
    EXPECT_NO_THROW(TAG2_SUB5_FILL(sub5));

    // String Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub5 str(sub5.raw());
        TAG2_SUB5_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub5 copy(sub5);
        TAG2_SUB5_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub5 move(std::move(sub5));
        TAG2_SUB5_EQ(move);
    }
}

TEST(Tag2Sub5, Assignment) {
    OpenPGP::Subpacket::Tag2::Sub5 sub5;
    EXPECT_NO_THROW(TAG2_SUB5_FILL(sub5));

    // Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub5 copy;
        copy = sub5;
        TAG2_SUB5_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub5 move;
        move = std::move(sub5);
        TAG2_SUB5_EQ(move);
    }
}

TEST(Tag2Sub5, read_write) {
    const std::string raw = std::string(1, level) + std::string(1, amount);

    OpenPGP::Subpacket::Tag2::Sub5 sub5(raw);
    TAG2_SUB5_EQ(sub5);
    EXPECT_EQ(sub5.raw(), raw);
}

TEST(Tag2Sub5, set_get) {
    OpenPGP::Subpacket::Tag2::Sub5 sub5;
    TAG2_SUB5_FILL(sub5);
    TAG2_SUB5_EQ(sub5);
}

TEST(Tag2Sub5, clone) {
    OpenPGP::Subpacket::Tag2::Sub5 sub5;
    EXPECT_NO_THROW(TAG2_SUB5_FILL(sub5));

    OpenPGP::Subpacket::Sub::Ptr clone = sub5.clone();
    EXPECT_NE(&sub5, clone.get());
    TAG2_SUB5_EQ(*std::static_pointer_cast<OpenPGP::Subpacket::Tag2::Sub5>(clone));
}
