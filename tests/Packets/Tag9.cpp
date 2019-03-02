#include <gtest/gtest.h>

#include "Packets/Tag9.h"

static const std::string encrypted_data = "";

static void TAG9_FILL(OpenPGP::Packet::Tag9 & tag9) {
    tag9.set_encrypted_data(encrypted_data);
}

#define TAG9_EQ(tag9)                                       \
    EXPECT_EQ((tag9).get_encrypted_data(), encrypted_data);

TEST(Tag9, Constructor) {
    // Default constructor
    OpenPGP::Packet::Tag9 tag9;

    EXPECT_EQ(tag9.raw(), "");
    EXPECT_NO_THROW(TAG9_FILL(tag9));

    // String Constructor
    {
        OpenPGP::Packet::Tag9 str(tag9.raw());
        TAG9_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Packet::Tag9 copy(tag9);
        TAG9_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Packet::Tag9 move(std::move(tag9));
        TAG9_EQ(move);
    }
}

TEST(Tag9, Assignment) {
    OpenPGP::Packet::Tag9 tag9;
    EXPECT_NO_THROW(TAG9_FILL(tag9));

    // Assignment
    {
        OpenPGP::Packet::Tag9 copy;
        copy = tag9;
        TAG9_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Packet::Tag9 move;
        move = std::move(tag9);
        TAG9_EQ(move);
    }
}

TEST(Tag9, read_write) {
    OpenPGP::Packet::Tag9 tag9(encrypted_data);
    TAG9_EQ(tag9);

    EXPECT_EQ(tag9.raw(), encrypted_data);
}

TEST(Tag9, set_get) {
    OpenPGP::Packet::Tag9 tag9;
    EXPECT_NO_THROW(TAG9_FILL(tag9));
    TAG9_EQ(tag9);
}

TEST(Tag9, clone) {
    OpenPGP::Packet::Tag9 tag9;
    EXPECT_NO_THROW(TAG9_FILL(tag9));

    OpenPGP::Packet::Tag::Ptr clone = tag9.clone();
    EXPECT_NE(&tag9, clone.get());
    TAG9_EQ(*std::static_pointer_cast<OpenPGP::Packet::Tag9>(clone));
}
