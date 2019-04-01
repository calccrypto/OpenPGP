#include <gtest/gtest.h>

#include "Packets/Tag2/Sub10.h"

static const std::string stuff = "";

static void TAG2_SUB10_FILL(OpenPGP::Subpacket::Tag2::Sub10 & sub10) {
    sub10.set_stuff(stuff);
}

#define TAG2_SUB10_EQ(sub10)                    \
    EXPECT_EQ((sub10).get_stuff(), stuff);      \
    EXPECT_EQ((sub10).valid(true), OpenPGP::Status::SUCCESS);

TEST(Tag2Sub10, Constructor) {
    // Default constructor
    OpenPGP::Subpacket::Tag2::Sub10 sub10;

    EXPECT_EQ(sub10.raw(), stuff);
    EXPECT_NO_THROW(TAG2_SUB10_FILL(sub10));

    // String Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub10 str(sub10.raw());
        TAG2_SUB10_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub10 copy(sub10);
        TAG2_SUB10_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub10 move(std::move(sub10));
        TAG2_SUB10_EQ(move);
    }
}

TEST(Tag2Sub10, Assignment) {
    OpenPGP::Subpacket::Tag2::Sub10 sub10;
    EXPECT_NO_THROW(TAG2_SUB10_FILL(sub10));

    // Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub10 copy;
        copy = sub10;
        TAG2_SUB10_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub10 move;
        move = std::move(sub10);
        TAG2_SUB10_EQ(move);
    }
}

TEST(Tag2Sub10, read_write) {
    const std::string raw = stuff;

    OpenPGP::Subpacket::Tag2::Sub10 sub10(raw);
    TAG2_SUB10_EQ(sub10);
    EXPECT_EQ(sub10.raw(), raw);
}

TEST(Tag2Sub10, show) {
    OpenPGP::Subpacket::Tag2::Sub10 sub10;
    EXPECT_NO_THROW(TAG2_SUB10_FILL(sub10));
    EXPECT_NO_THROW(sub10.show());
}

TEST(Tag2Sub10, set_get) {
    OpenPGP::Subpacket::Tag2::Sub10 sub10;
    TAG2_SUB10_FILL(sub10);
    TAG2_SUB10_EQ(sub10);
}

TEST(Tag2Sub10, clone) {
    OpenPGP::Subpacket::Tag2::Sub10 sub10;
    EXPECT_NO_THROW(TAG2_SUB10_FILL(sub10));

    OpenPGP::Subpacket::Sub::Ptr clone = sub10.clone();
    EXPECT_NE(&sub10, clone.get());
    TAG2_SUB10_EQ(*std::static_pointer_cast<OpenPGP::Subpacket::Tag2::Sub10>(clone));
}
