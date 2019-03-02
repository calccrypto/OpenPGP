#include <gtest/gtest.h>

#include "Packets/Tag63.h"

static const std::string stream("\x00\x01\x02\x03\x04\x05\x06\x07", 8);

static void TAG63_FILL(OpenPGP::Packet::Tag63 & tag63) {
    tag63.set_stream(stream);
}

#define TAG63_EQ(tag63)                         \
    EXPECT_EQ((tag63).get_stream(), stream);

TEST(Tag63, Constructor) {
    // Default constructor
    OpenPGP::Packet::Tag63 tag63;

    EXPECT_EQ(tag63.raw(), "");
    EXPECT_NO_THROW(TAG63_FILL(tag63));

    // String Constructor
    {
        OpenPGP::Packet::Tag63 str(tag63.raw());
        TAG63_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Packet::Tag63 copy(tag63);
        TAG63_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Packet::Tag63 move(std::move(tag63));
        TAG63_EQ(move);
    }
}

TEST(Tag63, Assignment) {
    OpenPGP::Packet::Tag63 tag63;
    EXPECT_NO_THROW(TAG63_FILL(tag63));

    // Assignment
    {
        OpenPGP::Packet::Tag63 copy;
        copy = tag63;
        TAG63_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Packet::Tag63 move;
        move = std::move(tag63);
        TAG63_EQ(move);
    }
}

TEST(Tag63, read_write) {
    OpenPGP::Packet::Tag63 tag63(stream);
    TAG63_EQ(tag63);
    EXPECT_EQ(tag63.raw(), stream);
}

TEST(Tag63, set_get) {
    OpenPGP::Packet::Tag63 tag63;
    EXPECT_NO_THROW(TAG63_FILL(tag63));
    TAG63_EQ(tag63);
}

TEST(Tag63, clone) {
    OpenPGP::Packet::Tag63 tag63;
    EXPECT_NO_THROW(TAG63_FILL(tag63));

    OpenPGP::Packet::Tag::Ptr clone = tag63.clone();
    EXPECT_NE(&tag63, clone.get());
    TAG63_EQ(*std::static_pointer_cast<OpenPGP::Packet::Tag63>(clone));
}
