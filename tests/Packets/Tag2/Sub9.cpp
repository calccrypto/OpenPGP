#include <gtest/gtest.h>

#include "Packets/Tag2/Sub9.h"

static const uint32_t dt = 0;

static void TAG2_SUB9_FILL(OpenPGP::Subpacket::Tag2::Sub9 & sub9) {
    sub9.set_dt(dt);
}

#define TAG2_SUB9_EQ(sub9)                      \
    EXPECT_EQ((sub9).get_dt(), dt);

TEST(Tag2Sub9, Constructor) {
    // Default constructor
    OpenPGP::Subpacket::Tag2::Sub9 sub9;

    EXPECT_EQ(sub9.raw(), std::string("\x00\x00\x00\x00", 4));
    EXPECT_NO_THROW(TAG2_SUB9_FILL(sub9));

    // String Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub9 str(sub9.raw());
        TAG2_SUB9_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub9 copy(sub9);
        TAG2_SUB9_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub9 move(std::move(sub9));
        TAG2_SUB9_EQ(move);
    }
}

TEST(Tag2Sub9, Assignment) {
    OpenPGP::Subpacket::Tag2::Sub9 sub9;
    EXPECT_NO_THROW(TAG2_SUB9_FILL(sub9));

    // Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub9 copy;
        copy = sub9;
        TAG2_SUB9_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub9 move;
        move = std::move(sub9);
        TAG2_SUB9_EQ(move);
    }
}

TEST(Tag2Sub9, read_write) {
    const std::string raw = unhexlify(makehex(dt, 8));

    OpenPGP::Subpacket::Tag2::Sub9 sub9(raw);
    TAG2_SUB9_EQ(sub9);
    EXPECT_EQ(sub9.raw(), raw);
}

TEST(Tag2Sub9, set_get) {
    OpenPGP::Subpacket::Tag2::Sub9 sub9;
    TAG2_SUB9_FILL(sub9);
    TAG2_SUB9_EQ(sub9);
}

TEST(Tag2Sub9, clone) {
    OpenPGP::Subpacket::Tag2::Sub9 sub9;
    EXPECT_NO_THROW(TAG2_SUB9_FILL(sub9));

    OpenPGP::Subpacket::Sub::Ptr clone = sub9.clone();
    EXPECT_NE(&sub9, clone.get());
    TAG2_SUB9_EQ(*std::static_pointer_cast<OpenPGP::Subpacket::Tag2::Sub9>(clone));
}
