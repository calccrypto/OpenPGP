#include <gtest/gtest.h>

#include "Packets/Tag19.h"

static const std::string hash(20, '\x00');

static void TAG19_FILL(OpenPGP::Packet::Tag19 & tag19) {
    tag19.set_hash(hash);
}

#define TAG19_EQ(tag19)                                         \
    EXPECT_EQ((tag19).get_hash(), hash);                        \
    EXPECT_EQ((tag19).valid(true), OpenPGP::Status::SUCCESS);

TEST(Tag19, Constructor) {
    // Default constructor
    OpenPGP::Packet::Tag19 tag19;

    EXPECT_EQ(tag19.raw(), "");
    EXPECT_NO_THROW(TAG19_FILL(tag19));

    // String Constructor
    {
        OpenPGP::Packet::Tag19 str(tag19.raw());
        TAG19_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Packet::Tag19 copy(tag19);
        TAG19_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Packet::Tag19 move(std::move(tag19));
        TAG19_EQ(move);
    }
}

TEST(Tag19, Assignment) {
    OpenPGP::Packet::Tag19 tag19;
    EXPECT_NO_THROW(TAG19_FILL(tag19));

    // Assignment
    {
        OpenPGP::Packet::Tag19 copy;
        copy = tag19;
        TAG19_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Packet::Tag19 move;
        move = std::move(tag19);
        TAG19_EQ(move);
    }
}

TEST(Tag19, read_write) {
    OpenPGP::Packet::Tag19 tag19(hash);
    TAG19_EQ(tag19);
    EXPECT_EQ(tag19.raw(), hash);
}

TEST(Tag19, set_get) {
    OpenPGP::Packet::Tag19 tag19;
    EXPECT_NO_THROW(TAG19_FILL(tag19));
    TAG19_EQ(tag19);
}

TEST(Tag19, clone) {
    OpenPGP::Packet::Tag19 tag19;
    EXPECT_NO_THROW(TAG19_FILL(tag19));

    OpenPGP::Packet::Tag::Ptr clone = tag19.clone();
    EXPECT_NE(&tag19, clone.get());
    TAG19_EQ(*std::static_pointer_cast<OpenPGP::Packet::Tag19>(clone));
}
