#include <gtest/gtest.h>

#include "Packets/Tag2/Sub28.h"

static const std::string signer = "";

static void TAG2_SUB28_FILL(OpenPGP::Subpacket::Tag2::Sub28 & sub28) {
    sub28.set_signer(signer);
}

#define TAG2_SUB28_EQ(sub28)                    \
    EXPECT_EQ((sub28).get_signer(), signer);

TEST(Tag2Sub28, Constructor) {
    // Default constructor
    OpenPGP::Subpacket::Tag2::Sub28 sub28;

    EXPECT_EQ(sub28.raw(), "");
    EXPECT_NO_THROW(TAG2_SUB28_FILL(sub28));

    // String Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub28 str(sub28.raw());
        TAG2_SUB28_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub28 copy(sub28);
        TAG2_SUB28_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub28 move(std::move(sub28));
        TAG2_SUB28_EQ(move);
    }
}

TEST(Tag2Sub28, Assignment) {
    OpenPGP::Subpacket::Tag2::Sub28 sub28;
    EXPECT_NO_THROW(TAG2_SUB28_FILL(sub28));

    // Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub28 copy;
        copy = sub28;
        TAG2_SUB28_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub28 move;
        move = std::move(sub28);
        TAG2_SUB28_EQ(move);
    }
}

TEST(Tag2Sub28, read_write) {
    const std::string raw = signer;

    OpenPGP::Subpacket::Tag2::Sub28 sub28(raw);
    TAG2_SUB28_EQ(sub28);
    EXPECT_EQ(sub28.raw(), raw);
}

TEST(Tag2Sub28, set_get) {
    OpenPGP::Subpacket::Tag2::Sub28 sub28;
    TAG2_SUB28_FILL(sub28);
    TAG2_SUB28_EQ(sub28);
}

TEST(Tag2Sub28, clone) {
    OpenPGP::Subpacket::Tag2::Sub28 sub28;
    EXPECT_NO_THROW(TAG2_SUB28_FILL(sub28));

    OpenPGP::Subpacket::Sub::Ptr clone = sub28.clone();
    EXPECT_NE(&sub28, clone.get());
    TAG2_SUB28_EQ(*std::static_pointer_cast<OpenPGP::Subpacket::Tag2::Sub28>(clone));
}
