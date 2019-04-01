#include <gtest/gtest.h>

#include "Packets/Tag2/Sub4.h"

static const bool exportable = 0;

static void TAG2_SUB4_FILL(OpenPGP::Subpacket::Tag2::Sub4 & sub4) {
    sub4.set_exportable(exportable);
}

#define TAG2_SUB4_EQ(sub4)                          \
    EXPECT_EQ((sub4).get_exportable(), exportable); \
    EXPECT_EQ((sub4).valid(true), OpenPGP::Status::SUCCESS);

TEST(Tag2Sub4, Constructor) {
    // Default constructor
    OpenPGP::Subpacket::Tag2::Sub4 sub4;

    EXPECT_EQ(sub4.raw(), std::string(1, exportable));
    EXPECT_NO_THROW(TAG2_SUB4_FILL(sub4));

    // String Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub4 str(sub4.raw());
        TAG2_SUB4_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub4 copy(sub4);
        TAG2_SUB4_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub4 move(std::move(sub4));
        TAG2_SUB4_EQ(move);
    }
}

TEST(Tag2Sub4, Assignment) {
    OpenPGP::Subpacket::Tag2::Sub4 sub4;
    EXPECT_NO_THROW(TAG2_SUB4_FILL(sub4));

    // Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub4 copy;
        copy = sub4;
        TAG2_SUB4_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub4 move;
        move = std::move(sub4);
        TAG2_SUB4_EQ(move);
    }
}

TEST(Tag2Sub4, read_write) {
    const std::string raw(1, exportable);

    OpenPGP::Subpacket::Tag2::Sub4 sub4(raw);
    TAG2_SUB4_EQ(sub4);
    EXPECT_EQ(sub4.raw(), raw);
}

TEST(Tag2Sub4, show) {
    OpenPGP::Subpacket::Tag2::Sub4 sub4;
    EXPECT_NO_THROW(TAG2_SUB4_FILL(sub4));
    EXPECT_NO_THROW(sub4.show());
}

TEST(Tag2Sub4, set_get) {
    OpenPGP::Subpacket::Tag2::Sub4 sub4;
    TAG2_SUB4_FILL(sub4);
    TAG2_SUB4_EQ(sub4);
}

TEST(Tag2Sub4, clone) {
    OpenPGP::Subpacket::Tag2::Sub4 sub4;
    EXPECT_NO_THROW(TAG2_SUB4_FILL(sub4));

    OpenPGP::Subpacket::Sub::Ptr clone = sub4.clone();
    EXPECT_NE(&sub4, clone.get());
    TAG2_SUB4_EQ(*std::static_pointer_cast<OpenPGP::Subpacket::Tag2::Sub4>(clone));
}
