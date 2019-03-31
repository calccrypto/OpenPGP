#include <gtest/gtest.h>

#include "Packets/Tag2/Sub6.h"

static const std::string regex = "";

static void TAG2_SUB6_FILL(OpenPGP::Subpacket::Tag2::Sub6 & sub6) {
    sub6.set_regex(regex);
}

#define TAG2_SUB6_EQ(sub6)                      \
    EXPECT_EQ((sub6).get_regex(), regex);       \
    EXPECT_EQ((sub6).valid(true), OpenPGP::Status::SUCCESS);

TEST(Tag2Sub6, Constructor) {
    // Default constructor
    OpenPGP::Subpacket::Tag2::Sub6 sub6;

    EXPECT_EQ(sub6.raw(), regex + zero);
    EXPECT_NO_THROW(TAG2_SUB6_FILL(sub6));

    // String Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub6 str(sub6.raw());
        TAG2_SUB6_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub6 copy(sub6);
        TAG2_SUB6_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub6 move(std::move(sub6));
        TAG2_SUB6_EQ(move);
    }
}

TEST(Tag2Sub6, Assignment) {
    OpenPGP::Subpacket::Tag2::Sub6 sub6;
    EXPECT_NO_THROW(TAG2_SUB6_FILL(sub6));

    // Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub6 copy;
        copy = sub6;
        TAG2_SUB6_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub6 move;
        move = std::move(sub6);
        TAG2_SUB6_EQ(move);
    }
}

TEST(Tag2Sub6, read_write) {
    const std::string raw = regex;

    OpenPGP::Subpacket::Tag2::Sub6 sub6(raw);
    TAG2_SUB6_EQ(sub6);
    EXPECT_EQ(sub6.raw(), raw + zero);
}

TEST(Tag2Sub6, set_get) {
    OpenPGP::Subpacket::Tag2::Sub6 sub6;
    TAG2_SUB6_FILL(sub6);
    TAG2_SUB6_EQ(sub6);
}

TEST(Tag2Sub6, clone) {
    OpenPGP::Subpacket::Tag2::Sub6 sub6;
    EXPECT_NO_THROW(TAG2_SUB6_FILL(sub6));

    OpenPGP::Subpacket::Sub::Ptr clone = sub6.clone();
    EXPECT_NE(&sub6, clone.get());
    TAG2_SUB6_EQ(*std::static_pointer_cast<OpenPGP::Subpacket::Tag2::Sub6>(clone));
}
