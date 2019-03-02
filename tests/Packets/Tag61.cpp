#include <gtest/gtest.h>

#include "Packets/Tag61.h"

static const std::string stream("\x00\x01\x02\x03\x04\x05\x06\x07", 8);

static void TAG61_FILL(OpenPGP::Packet::Tag61 & tag61) {
    tag61.set_stream(stream);
}

#define TAG61_EQ(tag61)                         \
    EXPECT_EQ((tag61).get_stream(), stream);

TEST(Tag61, Constructor) {
    // Default constructor
    OpenPGP::Packet::Tag61 tag61;

    EXPECT_EQ(tag61.raw(), "");
    EXPECT_NO_THROW(TAG61_FILL(tag61));

    // String Constructor
    {
        OpenPGP::Packet::Tag61 str(tag61.raw());
        TAG61_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Packet::Tag61 copy(tag61);
        TAG61_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Packet::Tag61 move(std::move(tag61));
        TAG61_EQ(move);
    }
}

TEST(Tag61, Assignment) {
    OpenPGP::Packet::Tag61 tag61;
    EXPECT_NO_THROW(TAG61_FILL(tag61));

    // Assignment
    {
        OpenPGP::Packet::Tag61 copy;
        copy = tag61;
        TAG61_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Packet::Tag61 move;
        move = std::move(tag61);
        TAG61_EQ(move);
    }
}

TEST(Tag61, read_write) {
    OpenPGP::Packet::Tag61 tag61(stream);
    TAG61_EQ(tag61);
    EXPECT_EQ(tag61.raw(), stream);
}

TEST(Tag61, set_get) {
    OpenPGP::Packet::Tag61 tag61;
    EXPECT_NO_THROW(TAG61_FILL(tag61));
    TAG61_EQ(tag61);
}

TEST(Tag61, clone) {
    OpenPGP::Packet::Tag61 tag61;
    EXPECT_NO_THROW(TAG61_FILL(tag61));

    OpenPGP::Packet::Tag::Ptr clone = tag61.clone();
    EXPECT_NE(&tag61, clone.get());
    TAG61_EQ(*std::static_pointer_cast<OpenPGP::Packet::Tag61>(clone));
}
