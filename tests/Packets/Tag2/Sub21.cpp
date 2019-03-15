#include <gtest/gtest.h>

#include "Packets/Tag2/Sub21.h"

static const std::string pha = std::string(1, OpenPGP::Hash::ID::SHA1);

static void TAG2_SUB21_FILL(OpenPGP::Subpacket::Tag2::Sub21 & sub21) {
    sub21.set_pha(pha);
}

#define TAG2_SUB21_EQ(sub21)                    \
    EXPECT_EQ((sub21).get_pha(), pha);

TEST(Tag2Sub21, Constructor) {
    // Default constructor
    OpenPGP::Subpacket::Tag2::Sub21 sub21;

    EXPECT_EQ(sub21.raw(), "");
    EXPECT_NO_THROW(TAG2_SUB21_FILL(sub21));

    // String Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub21 str(sub21.raw());
        TAG2_SUB21_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub21 copy(sub21);
        TAG2_SUB21_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub21 move(std::move(sub21));
        TAG2_SUB21_EQ(move);
    }
}

TEST(Tag2Sub21, Assignment) {
    OpenPGP::Subpacket::Tag2::Sub21 sub21;
    EXPECT_NO_THROW(TAG2_SUB21_FILL(sub21));

    // Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub21 copy;
        copy = sub21;
        TAG2_SUB21_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub21 move;
        move = std::move(sub21);
        TAG2_SUB21_EQ(move);
    }
}

TEST(Tag2Sub21, read_write) {
    const std::string raw = pha;

    OpenPGP::Subpacket::Tag2::Sub21 sub21(raw);
    TAG2_SUB21_EQ(sub21);
    EXPECT_EQ(sub21.raw(), raw);
}

TEST(Tag2Sub21, set_get) {
    OpenPGP::Subpacket::Tag2::Sub21 sub21;
    TAG2_SUB21_FILL(sub21);
    TAG2_SUB21_EQ(sub21);
}

TEST(Tag2Sub21, clone) {
    OpenPGP::Subpacket::Tag2::Sub21 sub21;
    EXPECT_NO_THROW(TAG2_SUB21_FILL(sub21));

    OpenPGP::Subpacket::Sub::Ptr clone = sub21.clone();
    EXPECT_NE(&sub21, clone.get());
    TAG2_SUB21_EQ(*std::static_pointer_cast<OpenPGP::Subpacket::Tag2::Sub21>(clone));
}
