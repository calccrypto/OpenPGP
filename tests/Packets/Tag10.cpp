#include <gtest/gtest.h>

#include "Packets/Tag10.h"

static void TAG10_FILL(OpenPGP::Packet::Tag10 & tag10) {
    tag10.set_pgp(OpenPGP::Packet::Tag10::body);
}

#define TAG10_EQ(tag10)                                         \
    EXPECT_EQ((tag10).get_pgp(), OpenPGP::Packet::Tag10::body);

TEST(Tag10, Constructor) {
    // Default constructor
    OpenPGP::Packet::Tag10 tag10;

    EXPECT_EQ(tag10.raw(), "PGP");
    EXPECT_NO_THROW(TAG10_FILL(tag10));

    // String Constructor
    {
        OpenPGP::Packet::Tag10 str(tag10.raw());
        TAG10_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Packet::Tag10 copy(tag10);
        TAG10_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Packet::Tag10 move(std::move(tag10));
        TAG10_EQ(move);
    }
}

TEST(Tag10, Assignment) {
    OpenPGP::Packet::Tag10 tag10;
    EXPECT_NO_THROW(TAG10_FILL(tag10));

    // Assignment
    {
        OpenPGP::Packet::Tag10 copy;
        copy = tag10;
        TAG10_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Packet::Tag10 move;
        move = std::move(tag10);
        TAG10_EQ(move);
    }
}

TEST(Tag10, read_write) {
    OpenPGP::Packet::Tag10 tag10(OpenPGP::Packet::Tag10::body);
    EXPECT_EQ(tag10.raw(), OpenPGP::Packet::Tag10::body);
}

TEST(Tag10, set_get) {
    OpenPGP::Packet::Tag10 tag10;
    EXPECT_NO_THROW(TAG10_FILL(tag10));
    TAG10_EQ(tag10);
}

TEST(Tag10, clone) {
    OpenPGP::Packet::Tag10 tag10;
    EXPECT_NO_THROW(TAG10_FILL(tag10));

    OpenPGP::Packet::Tag::Ptr clone = tag10.clone();
    EXPECT_NE(&tag10, clone.get());
    TAG10_EQ(*std::static_pointer_cast<OpenPGP::Packet::Tag10>(clone));
}
