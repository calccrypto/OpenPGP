#include <gtest/gtest.h>

#include "Packets/Tag2/Sub30.h"

static const std::string flags(1, OpenPGP::Subpacket::Tag2::Features_Flags::MODIFICATION_DETECTION);

static void TAG2_SUB30_FILL(OpenPGP::Subpacket::Tag2::Sub30 & sub30) {
    sub30.set_flags(flags);
}

#define TAG2_SUB30_EQ(sub30)                    \
    EXPECT_EQ((sub30).get_flags(), flags);

TEST(Tag2Sub30, Constructor) {
    // Default constructor
    OpenPGP::Subpacket::Tag2::Sub30 sub30;

    EXPECT_EQ(sub30.raw(), "");
    EXPECT_NO_THROW(TAG2_SUB30_FILL(sub30));

    // String Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub30 str(sub30.raw());
        TAG2_SUB30_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub30 copy(sub30);
        TAG2_SUB30_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub30 move(std::move(sub30));
        TAG2_SUB30_EQ(move);
    }
}

TEST(Tag2Sub30, Assignment) {
    OpenPGP::Subpacket::Tag2::Sub30 sub30;
    EXPECT_NO_THROW(TAG2_SUB30_FILL(sub30));

    // Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub30 copy;
        copy = sub30;
        TAG2_SUB30_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub30 move;
        move = std::move(sub30);
        TAG2_SUB30_EQ(move);
    }
}

TEST(Tag2Sub30, read_write) {
    const std::string raw = flags;

    OpenPGP::Subpacket::Tag2::Sub30 sub30(raw);
    TAG2_SUB30_EQ(sub30);
    EXPECT_EQ(sub30.raw(), raw);
}

TEST(Tag2Sub30, set_get) {
    OpenPGP::Subpacket::Tag2::Sub30 sub30;
    TAG2_SUB30_FILL(sub30);
    TAG2_SUB30_EQ(sub30);
}

TEST(Tag2Sub30, clone) {
    OpenPGP::Subpacket::Tag2::Sub30 sub30;
    EXPECT_NO_THROW(TAG2_SUB30_FILL(sub30));

    OpenPGP::Subpacket::Sub::Ptr clone = sub30.clone();
    EXPECT_NE(&sub30, clone.get());
    TAG2_SUB30_EQ(*std::static_pointer_cast<OpenPGP::Subpacket::Tag2::Sub30>(clone));
}
