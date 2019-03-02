#include <gtest/gtest.h>

#include "Packets/Tag2/Sub3.h"

static const uint32_t dt = 0;

static void TAG2_SUB3_FILL(OpenPGP::Subpacket::Tag2::Sub3 & sub3) {
    sub3.set_dt(dt);
}

#define TAG2_SUB3_EQ(sub3)                      \
    EXPECT_EQ((sub3).get_dt(), dt);

TEST(Tag2Sub3, Constructor) {
    // Default constructor
    OpenPGP::Subpacket::Tag2::Sub3 sub3;

    EXPECT_EQ(sub3.raw(), std::string("\x00\x00\x00\x00", 4));
    EXPECT_NO_THROW(TAG2_SUB3_FILL(sub3));

    // String Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub3 str(sub3.raw());
        TAG2_SUB3_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub3 copy(sub3);
        TAG2_SUB3_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub3 move(std::move(sub3));
        TAG2_SUB3_EQ(move);
    }
}

TEST(Tag2Sub3, Assignment) {
    OpenPGP::Subpacket::Tag2::Sub3 sub3;
    EXPECT_NO_THROW(TAG2_SUB3_FILL(sub3));

    // Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub3 copy;
        copy = sub3;
        TAG2_SUB3_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub3 move;
        move = std::move(sub3);
        TAG2_SUB3_EQ(move);
    }
}

TEST(Tag2Sub3, read_write) {
    const std::string raw = unhexlify(makehex(dt, 8));

    OpenPGP::Subpacket::Tag2::Sub3 sub3(raw);
    TAG2_SUB3_EQ(sub3);
    EXPECT_EQ(sub3.raw(), raw);
}

TEST(Tag2Sub3, set_get) {
    OpenPGP::Subpacket::Tag2::Sub3 sub3;
    TAG2_SUB3_FILL(sub3);
    TAG2_SUB3_EQ(sub3);
}

TEST(Tag2Sub3, clone) {
    OpenPGP::Subpacket::Tag2::Sub3 sub3;
    EXPECT_NO_THROW(TAG2_SUB3_FILL(sub3));

    OpenPGP::Subpacket::Sub::Ptr clone = sub3.clone();
    EXPECT_NE(&sub3, clone.get());
    TAG2_SUB3_EQ(*std::static_pointer_cast<OpenPGP::Subpacket::Tag2::Sub3>(clone));
}
