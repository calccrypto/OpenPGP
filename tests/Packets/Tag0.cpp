#include <gtest/gtest.h>

#include "Packets/Tag0.h"

static void TAG0_FILL(OpenPGP::Packet::Tag0 &) {}

#define TAG0_EQ(tag0)

TEST(Tag0, Constructor) {
    // Default constructor
    OpenPGP::Packet::Tag0 tag0;

    EXPECT_EQ(tag0.raw(), "");
    EXPECT_NO_THROW(TAG0_FILL(tag0));

    // String Constructor
    {
        OpenPGP::Packet::Tag0 str(tag0.raw());
        TAG0_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Packet::Tag0 copy(tag0);
        TAG0_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Packet::Tag0 move(std::move(tag0));
        TAG0_EQ(move);
    }
}

TEST(Tag0, Assignment) {
    OpenPGP::Packet::Tag0 tag0;
    EXPECT_NO_THROW(TAG0_FILL(tag0));

    // Assignment
    {
        OpenPGP::Packet::Tag0 copy;
        copy = tag0;
        TAG0_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Packet::Tag0 move;
        move = std::move(tag0);
        TAG0_EQ(move);
    }
}

TEST(Tag0, read_write) {
    const std::string raw = "";

    OpenPGP::Packet::Tag0 tag0(raw);
    TAG0_EQ(tag0);

    EXPECT_EQ(tag0.raw(), raw);
}

TEST(Tag0, set_get) {
    OpenPGP::Packet::Tag0 tag0;
    EXPECT_NO_THROW(TAG0_FILL(tag0));
    TAG0_EQ(tag0);
}

TEST(Tag0, clone) {
    OpenPGP::Packet::Tag0 tag0;
    EXPECT_NO_THROW(TAG0_FILL(tag0));

    OpenPGP::Packet::Tag::Ptr clone = tag0.clone();
    EXPECT_NE(&tag0, clone.get());
    TAG0_EQ(*std::static_pointer_cast<OpenPGP::Packet::Tag0>(clone));
}
