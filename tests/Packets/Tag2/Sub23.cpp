#include <gtest/gtest.h>

#include "Packets/Tag2/Sub23.h"

static const std::string flags = std::string(1, '\x80');

static void TAG2_SUB23_FILL(OpenPGP::Subpacket::Tag2::Sub23 & sub23) {
    sub23.set_flags(flags);
}

#define TAG2_SUB23_EQ(sub23)                    \
    EXPECT_EQ((sub23).get_flags(), flags);

TEST(Tag2Sub23, Constructor) {
    // Default constructor
    OpenPGP::Subpacket::Tag2::Sub23 sub23;

    EXPECT_EQ(sub23.raw(), "");
    EXPECT_NO_THROW(TAG2_SUB23_FILL(sub23));

    // String Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub23 str(sub23.raw());
        TAG2_SUB23_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub23 copy(sub23);
        TAG2_SUB23_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub23 move(std::move(sub23));
        TAG2_SUB23_EQ(move);
    }
}

TEST(Tag2Sub23, Assignment) {
    OpenPGP::Subpacket::Tag2::Sub23 sub23;
    EXPECT_NO_THROW(TAG2_SUB23_FILL(sub23));

    // Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub23 copy;
        copy = sub23;
        TAG2_SUB23_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub23 move;
        move = std::move(sub23);
        TAG2_SUB23_EQ(move);
    }
}

TEST(Tag2Sub23, read_write) {
    const std::string raw = flags;

    OpenPGP::Subpacket::Tag2::Sub23 sub23(raw);
    TAG2_SUB23_EQ(sub23);
    EXPECT_EQ(sub23.raw(), raw);
}

TEST(Tag2Sub23, set_get) {
    OpenPGP::Subpacket::Tag2::Sub23 sub23;
    TAG2_SUB23_FILL(sub23);
    TAG2_SUB23_EQ(sub23);
}

TEST(Tag2Sub23, clone) {
    OpenPGP::Subpacket::Tag2::Sub23 sub23;
    EXPECT_NO_THROW(TAG2_SUB23_FILL(sub23));

    OpenPGP::Subpacket::Sub::Ptr clone = sub23.clone();
    EXPECT_NE(&sub23, clone.get());
    TAG2_SUB23_EQ(*std::static_pointer_cast<OpenPGP::Subpacket::Tag2::Sub23>(clone));
}
