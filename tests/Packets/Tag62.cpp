#include <gtest/gtest.h>

#include "Packets/Tag62.h"

static const std::string stream("\x00\x01\x02\x03\x04\x05\x06\x07", 8);

static void TAG62_FILL(OpenPGP::Packet::Tag62 & tag62) {
    tag62.set_stream(stream);
}

#define TAG62_EQ(tag62)                                         \
    EXPECT_EQ((tag62).get_stream(), stream);                    \
    EXPECT_EQ((tag62).valid(true), OpenPGP::Status::SUCCESS);

TEST(Tag62, Constructor) {
    // Default constructor
    OpenPGP::Packet::Tag62 tag62;

    EXPECT_EQ(tag62.raw(), "");
    EXPECT_NO_THROW(TAG62_FILL(tag62));

    // String Constructor
    {
        OpenPGP::Packet::Tag62 str(tag62.raw());
        TAG62_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Packet::Tag62 copy(tag62);
        TAG62_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Packet::Tag62 move(std::move(tag62));
        TAG62_EQ(move);
    }
}

TEST(Tag62, Assignment) {
    OpenPGP::Packet::Tag62 tag62;
    EXPECT_NO_THROW(TAG62_FILL(tag62));

    // Assignment
    {
        OpenPGP::Packet::Tag62 copy;
        copy = tag62;
        TAG62_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Packet::Tag62 move;
        move = std::move(tag62);
        TAG62_EQ(move);
    }
}

TEST(Tag62, read_write) {
    OpenPGP::Packet::Tag62 tag62(stream);
    TAG62_EQ(tag62);
    EXPECT_EQ(tag62.raw(), stream);
}

TEST(Tag62, set_get) {
    OpenPGP::Packet::Tag62 tag62;
    EXPECT_NO_THROW(TAG62_FILL(tag62));
    TAG62_EQ(tag62);
}

TEST(Tag62, clone) {
    OpenPGP::Packet::Tag62 tag62;
    EXPECT_NO_THROW(TAG62_FILL(tag62));

    OpenPGP::Packet::Tag::Ptr clone = tag62.clone();
    EXPECT_NE(&tag62, clone.get());
    TAG62_EQ(*std::static_pointer_cast<OpenPGP::Packet::Tag62>(clone));
}
