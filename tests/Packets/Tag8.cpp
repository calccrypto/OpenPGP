#include <vector>

#include <gtest/gtest.h>

#include "common/includes.h"
#include "Packets/Tag8.h"
#include "testvectors/msg.h"

static void TAG8_FILL(OpenPGP::Packet::Tag8 & tag8, const uint8_t comp) {
    tag8.set_comp(comp);
    tag8.set_data(MESSAGE);
}

#define TAG8_EQ(tag8, comp)                        \
    EXPECT_EQ((tag8).get_comp(), comp);            \
    EXPECT_EQ((tag8).get_data(), MESSAGE);         \

TEST(Tag8, Constructor) {
    // Default constructor
    OpenPGP::Packet::Tag8 tag8;

    EXPECT_EQ(tag8.raw(), std::string("\x00", 1));
    EXPECT_NO_THROW(TAG8_FILL(tag8, OpenPGP::Compression::ID::UNCOMPRESSED));

    // String Constructor
    {
        OpenPGP::Packet::Tag8 str(tag8.raw());
        TAG8_EQ(str, OpenPGP::Compression::ID::UNCOMPRESSED);
    }

    // Copy Constructor
    {
        OpenPGP::Packet::Tag8 copy(tag8);
        TAG8_EQ(copy, OpenPGP::Compression::ID::UNCOMPRESSED);
    }

    // Move Constructor
    {
        OpenPGP::Packet::Tag8 move(std::move(tag8));
        TAG8_EQ(move, OpenPGP::Compression::ID::UNCOMPRESSED);
    }
}

TEST(Tag8, Assignment) {
    OpenPGP::Packet::Tag8 tag8;
    EXPECT_NO_THROW(TAG8_FILL(tag8, OpenPGP::Compression::ID::UNCOMPRESSED));

    // Assignment
    {
        OpenPGP::Packet::Tag8 copy;
        copy = tag8;
        TAG8_EQ(copy, OpenPGP::Compression::ID::UNCOMPRESSED);
    }

    // Move Assignment
    {
        OpenPGP::Packet::Tag8 move;
        move = std::move(tag8);
        TAG8_EQ(move, OpenPGP::Compression::ID::UNCOMPRESSED);
    }
}

TEST(Tag8, read_write) {
    const std::string raw = std::string(1, OpenPGP::Compression::ID::UNCOMPRESSED) +
                            MESSAGE;

    OpenPGP::Packet::Tag8 tag8(raw);
    TAG8_EQ(tag8, OpenPGP::Compression::ID::UNCOMPRESSED);
    EXPECT_EQ(tag8.raw(), raw);
}

TEST(Tag8, set_get) {
    OpenPGP::Packet::Tag8 tag8;
    EXPECT_NO_THROW(TAG8_FILL(tag8, OpenPGP::Compression::ID::UNCOMPRESSED));
    TAG8_EQ(tag8, OpenPGP::Compression::ID::UNCOMPRESSED);
}

TEST(Tag8, clone) {
    OpenPGP::Packet::Tag8 tag8;
    EXPECT_NO_THROW(TAG8_FILL(tag8, OpenPGP::Compression::ID::UNCOMPRESSED));

    OpenPGP::Packet::Tag::Ptr clone = tag8.clone();
    EXPECT_NE(&tag8, clone.get());
    TAG8_EQ(*std::static_pointer_cast<OpenPGP::Packet::Tag8>(clone), OpenPGP::Compression::ID::UNCOMPRESSED);
}
