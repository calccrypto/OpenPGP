#include <gtest/gtest.h>

#include "Packets/Tag60.h"

static const std::string stream("\x00\x01\x02\x03\x04\x05\x06\x07", 8);

static void TAG60_FILL(OpenPGP::Packet::Tag60 & tag60) {
    tag60.set_stream(stream);
}

#define TAG60_EQ(tag60)                         \
    EXPECT_EQ((tag60).get_stream(), stream);

TEST(Tag60, Constructor) {
    // Default constructor
    OpenPGP::Packet::Tag60 tag60;

    EXPECT_EQ(tag60.raw(), "");
    EXPECT_NO_THROW(TAG60_FILL(tag60));

    // String Constructor
    {
        OpenPGP::Packet::Tag60 str(tag60.raw());
        TAG60_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Packet::Tag60 copy(tag60);
        TAG60_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Packet::Tag60 move(std::move(tag60));
        TAG60_EQ(move);
    }
}

TEST(Tag60, Assignment) {
    OpenPGP::Packet::Tag60 tag60;
    EXPECT_NO_THROW(TAG60_FILL(tag60));

    // Assignment
    {
        OpenPGP::Packet::Tag60 copy;
        copy = tag60;
        TAG60_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Packet::Tag60 move;
        move = std::move(tag60);
        TAG60_EQ(move);
    }
}

TEST(Tag60, read_write) {
    OpenPGP::Packet::Tag60 tag60(stream);
    TAG60_EQ(tag60);
    EXPECT_EQ(tag60.raw(), stream);
}

TEST(Tag60, set_get) {
    OpenPGP::Packet::Tag60 tag60;
    EXPECT_NO_THROW(TAG60_FILL(tag60));
    TAG60_EQ(tag60);
}

TEST(Tag60, clone) {
    OpenPGP::Packet::Tag60 tag60;
    EXPECT_NO_THROW(TAG60_FILL(tag60));

    OpenPGP::Packet::Tag::Ptr clone = tag60.clone();
    EXPECT_NE(&tag60, clone.get());
    TAG60_EQ(*std::static_pointer_cast<OpenPGP::Packet::Tag60>(clone));
}
