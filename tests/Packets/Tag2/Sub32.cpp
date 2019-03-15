#include <gtest/gtest.h>

#include "Packets/Tag2/Sub32.h"

static const OpenPGP::Packet::Tag2::Ptr embedded = nullptr;

static void TAG2_SUB32_FILL(OpenPGP::Subpacket::Tag2::Sub32 & sub32) {
    sub32.set_embedded(embedded);
}

#define TAG2_SUB32_EQ(sub32)                    \
    EXPECT_EQ((sub32).get_embedded(), embedded);

TEST(Tag2Sub32, Constructor) {
    // Default constructor
    OpenPGP::Subpacket::Tag2::Sub32 sub32;

    EXPECT_EQ(sub32.raw(), "");
    EXPECT_NO_THROW(TAG2_SUB32_FILL(sub32));

    // String Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub32 str(sub32.raw());
        TAG2_SUB32_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub32 copy(sub32);
        TAG2_SUB32_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub32 move(std::move(sub32));
        TAG2_SUB32_EQ(move);
    }
}

TEST(Tag2Sub32, Assignment) {
    OpenPGP::Subpacket::Tag2::Sub32 sub32;
    EXPECT_NO_THROW(TAG2_SUB32_FILL(sub32));

    // Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub32 copy;
        copy = sub32;
        TAG2_SUB32_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub32 move;
        move = std::move(sub32);
        TAG2_SUB32_EQ(move);
    }
}

TEST(Tag2Sub32, read_write) {
    const std::string raw = "";

    OpenPGP::Subpacket::Tag2::Sub32 sub32(raw);
    TAG2_SUB32_EQ(sub32);
    EXPECT_EQ(sub32.raw(), raw);
}

TEST(Tag2Sub32, set_get) {
    OpenPGP::Subpacket::Tag2::Sub32 sub32;
    TAG2_SUB32_FILL(sub32);
    TAG2_SUB32_EQ(sub32);
}

TEST(Tag2Sub32, clone) {
    OpenPGP::Subpacket::Tag2::Sub32 sub32;
    EXPECT_NO_THROW(TAG2_SUB32_FILL(sub32));

    OpenPGP::Subpacket::Sub::Ptr clone = sub32.clone();
    EXPECT_NE(&sub32, clone.get());
    TAG2_SUB32_EQ(*std::static_pointer_cast<OpenPGP::Subpacket::Tag2::Sub32>(clone));
}
