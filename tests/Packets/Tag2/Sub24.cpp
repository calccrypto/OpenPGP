#include <gtest/gtest.h>

#include "Packets/Tag2/Sub24.h"

static const std::string pks = "";

static void TAG2_SUB24_FILL(OpenPGP::Subpacket::Tag2::Sub24 & sub24) {
    sub24.set_pks(pks);
}

#define TAG2_SUB24_EQ(sub24)                    \
    EXPECT_EQ((sub24).get_pks(), pks);          \
    EXPECT_EQ((sub24).valid(true), OpenPGP::Status::SUCCESS);

TEST(Tag2Sub24, Constructor) {
    // Default constructor
    OpenPGP::Subpacket::Tag2::Sub24 sub24;

    EXPECT_EQ(sub24.raw(), "");
    EXPECT_NO_THROW(TAG2_SUB24_FILL(sub24));

    // String Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub24 str(sub24.raw());
        TAG2_SUB24_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub24 copy(sub24);
        TAG2_SUB24_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub24 move(std::move(sub24));
        TAG2_SUB24_EQ(move);
    }
}

TEST(Tag2Sub24, Assignment) {
    OpenPGP::Subpacket::Tag2::Sub24 sub24;
    EXPECT_NO_THROW(TAG2_SUB24_FILL(sub24));

    // Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub24 copy;
        copy = sub24;
        TAG2_SUB24_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub24 move;
        move = std::move(sub24);
        TAG2_SUB24_EQ(move);
    }
}

TEST(Tag2Sub24, read_write) {
    const std::string raw = pks;

    OpenPGP::Subpacket::Tag2::Sub24 sub24(raw);
    TAG2_SUB24_EQ(sub24);
    EXPECT_EQ(sub24.raw(), raw);
}

TEST(Tag2Sub24, show) {
    OpenPGP::Subpacket::Tag2::Sub24 sub24;
    EXPECT_NO_THROW(TAG2_SUB24_FILL(sub24));
    EXPECT_NO_THROW(sub24.show());
}

TEST(Tag2Sub24, set_get) {
    OpenPGP::Subpacket::Tag2::Sub24 sub24;
    TAG2_SUB24_FILL(sub24);
    TAG2_SUB24_EQ(sub24);
}

TEST(Tag2Sub24, clone) {
    OpenPGP::Subpacket::Tag2::Sub24 sub24;
    EXPECT_NO_THROW(TAG2_SUB24_FILL(sub24));

    OpenPGP::Subpacket::Sub::Ptr clone = sub24.clone();
    EXPECT_NE(&sub24, clone.get());
    TAG2_SUB24_EQ(*std::static_pointer_cast<OpenPGP::Subpacket::Tag2::Sub24>(clone));
}
