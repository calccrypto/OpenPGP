#include <gtest/gtest.h>

#include "Packets/Tag2/Sub7.h"

static const bool revocable = 0;

static void TAG2_SUB7_FILL(OpenPGP::Subpacket::Tag2::Sub7 & sub7) {
    sub7.set_revocable(revocable);
}

#define TAG2_SUB7_EQ(sub7)                                      \
    EXPECT_EQ((sub7).get_revocable(), revocable);               \
    EXPECT_EQ((sub7).valid(true), OpenPGP::Status::SUCCESS);

TEST(Tag2Sub7, Constructor) {
    // Default constructor
    OpenPGP::Subpacket::Tag2::Sub7 sub7;

    EXPECT_EQ(sub7.raw(), std::string(1, revocable));
    EXPECT_NO_THROW(TAG2_SUB7_FILL(sub7));

    // String Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub7 str(sub7.raw());
        TAG2_SUB7_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub7 copy(sub7);
        TAG2_SUB7_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub7 move(std::move(sub7));
        TAG2_SUB7_EQ(move);
    }
}

TEST(Tag2Sub7, Assignment) {
    OpenPGP::Subpacket::Tag2::Sub7 sub7;
    EXPECT_NO_THROW(TAG2_SUB7_FILL(sub7));

    // Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub7 copy;
        copy = sub7;
        TAG2_SUB7_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub7 move;
        move = std::move(sub7);
        TAG2_SUB7_EQ(move);
    }
}

TEST(Tag2Sub7, read_write) {
    const std::string raw(1, revocable);

    OpenPGP::Subpacket::Tag2::Sub7 sub7(raw);
    TAG2_SUB7_EQ(sub7);
    EXPECT_EQ(sub7.raw(), raw);
}

TEST(Tag2Sub7, show) {
    OpenPGP::Subpacket::Tag2::Sub7 sub7;
    EXPECT_NO_THROW(TAG2_SUB7_FILL(sub7));
    EXPECT_NO_THROW(sub7.show());
}

TEST(Tag2Sub7, set_get) {
    OpenPGP::Subpacket::Tag2::Sub7 sub7;
    TAG2_SUB7_FILL(sub7);
    TAG2_SUB7_EQ(sub7);
}

TEST(Tag2Sub7, clone) {
    OpenPGP::Subpacket::Tag2::Sub7 sub7;
    EXPECT_NO_THROW(TAG2_SUB7_FILL(sub7));

    OpenPGP::Subpacket::Sub::Ptr clone = sub7.clone();
    EXPECT_NE(&sub7, clone.get());
    TAG2_SUB7_EQ(*std::static_pointer_cast<OpenPGP::Subpacket::Tag2::Sub7>(clone));
}
