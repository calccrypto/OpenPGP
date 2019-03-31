#include <gtest/gtest.h>

#include "Packets/Tag2/Sub27.h"

static const std::string flags(1, OpenPGP::Subpacket::Tag2::Key_Flags::CERTIFY_OTHER_KEYS);

static void TAG2_SUB27_FILL(OpenPGP::Subpacket::Tag2::Sub27 & sub27) {
    sub27.set_flags(flags);
}

#define TAG2_SUB27_EQ(sub27)                    \
    EXPECT_EQ((sub27).get_flags(), flags);      \
    EXPECT_EQ((sub27).valid(true), OpenPGP::Status::SUCCESS);

TEST(Tag2Sub27, Constructor) {
    // Default constructor
    OpenPGP::Subpacket::Tag2::Sub27 sub27;

    EXPECT_EQ(sub27.raw(), "");
    EXPECT_NO_THROW(TAG2_SUB27_FILL(sub27));

    // String Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub27 str(sub27.raw());
        TAG2_SUB27_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub27 copy(sub27);
        TAG2_SUB27_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub27 move(std::move(sub27));
        TAG2_SUB27_EQ(move);
    }
}

TEST(Tag2Sub27, Assignment) {
    OpenPGP::Subpacket::Tag2::Sub27 sub27;
    EXPECT_NO_THROW(TAG2_SUB27_FILL(sub27));

    // Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub27 copy;
        copy = sub27;
        TAG2_SUB27_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub27 move;
        move = std::move(sub27);
        TAG2_SUB27_EQ(move);
    }
}

TEST(Tag2Sub27, read_write) {
    const std::string raw = flags;

    OpenPGP::Subpacket::Tag2::Sub27 sub27(raw);
    TAG2_SUB27_EQ(sub27);
    EXPECT_EQ(sub27.raw(), raw);
}

TEST(Tag2Sub27, set_get) {
    OpenPGP::Subpacket::Tag2::Sub27 sub27;
    TAG2_SUB27_FILL(sub27);
    TAG2_SUB27_EQ(sub27);
}

TEST(Tag2Sub27, clone) {
    OpenPGP::Subpacket::Tag2::Sub27 sub27;
    EXPECT_NO_THROW(TAG2_SUB27_FILL(sub27));

    OpenPGP::Subpacket::Sub::Ptr clone = sub27.clone();
    EXPECT_NE(&sub27, clone.get());
    TAG2_SUB27_EQ(*std::static_pointer_cast<OpenPGP::Subpacket::Tag2::Sub27>(clone));
}
