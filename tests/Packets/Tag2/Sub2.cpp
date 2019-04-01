#include <gtest/gtest.h>

#include "Packets/Tag2/Sub2.h"

static const uint32_t timestamp = 0;

static void TAG2_SUB2_FILL(OpenPGP::Subpacket::Tag2::Sub2 & sub2) {
    sub2.set_time(timestamp);
}

#define TAG2_SUB2_EQ(sub2)                      \
    EXPECT_EQ((sub2).get_time(), timestamp);    \
    EXPECT_EQ((sub2).valid(true), OpenPGP::Status::SUCCESS);

TEST(Tag2Sub2, Constructor) {
    // Default constructor
    OpenPGP::Subpacket::Tag2::Sub2 sub2;

    EXPECT_EQ(sub2.raw(), std::string("\x00\x00\x00\x00", 4));
    EXPECT_NO_THROW(TAG2_SUB2_FILL(sub2));

    // String Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub2 str(sub2.raw());
        TAG2_SUB2_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub2 copy(sub2);
        TAG2_SUB2_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub2 move(std::move(sub2));
        TAG2_SUB2_EQ(move);
    }
}

TEST(Tag2Sub2, Assignment) {
    OpenPGP::Subpacket::Tag2::Sub2 sub2;
    EXPECT_NO_THROW(TAG2_SUB2_FILL(sub2));

    // Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub2 copy;
        copy = sub2;
        TAG2_SUB2_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub2 move;
        move = std::move(sub2);
        TAG2_SUB2_EQ(move);
    }
}

TEST(Tag2Sub2, read_write) {
    const std::string raw = unhexlify(makehex(timestamp, 8));

    OpenPGP::Subpacket::Tag2::Sub2 sub2(raw);
    TAG2_SUB2_EQ(sub2);
    EXPECT_EQ(sub2.raw(), raw);
}

TEST(Tag2Sub2, show) {
    OpenPGP::Subpacket::Tag2::Sub2 sub2;
    EXPECT_NO_THROW(TAG2_SUB2_FILL(sub2));
    EXPECT_NO_THROW(sub2.show());
}

TEST(Tag2Sub2, set_get) {
    OpenPGP::Subpacket::Tag2::Sub2 sub2;
    TAG2_SUB2_FILL(sub2);
    TAG2_SUB2_EQ(sub2);
}

TEST(Tag2Sub2, clone) {
    OpenPGP::Subpacket::Tag2::Sub2 sub2;
    EXPECT_NO_THROW(TAG2_SUB2_FILL(sub2));

    OpenPGP::Subpacket::Sub::Ptr clone = sub2.clone();
    EXPECT_NE(&sub2, clone.get());
    TAG2_SUB2_EQ(*std::static_pointer_cast<OpenPGP::Subpacket::Tag2::Sub2>(clone));
}
