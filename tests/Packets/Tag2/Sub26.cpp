#include <gtest/gtest.h>

#include "Packets/Tag2/Sub26.h"

static const std::string uri = "";

static void TAG2_SUB26_FILL(OpenPGP::Subpacket::Tag2::Sub26 & sub26) {
    sub26.set_uri(uri);
}

#define TAG2_SUB26_EQ(sub26)                    \
    EXPECT_EQ((sub26).get_uri(), uri);          \
    EXPECT_EQ((sub26).valid(true), OpenPGP::Status::SUCCESS);

TEST(Tag2Sub26, Constructor) {
    // Default constructor
    OpenPGP::Subpacket::Tag2::Sub26 sub26;

    EXPECT_EQ(sub26.raw(), "");
    EXPECT_NO_THROW(TAG2_SUB26_FILL(sub26));

    // String Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub26 str(sub26.raw());
        TAG2_SUB26_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub26 copy(sub26);
        TAG2_SUB26_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub26 move(std::move(sub26));
        TAG2_SUB26_EQ(move);
    }
}

TEST(Tag2Sub26, Assignment) {
    OpenPGP::Subpacket::Tag2::Sub26 sub26;
    EXPECT_NO_THROW(TAG2_SUB26_FILL(sub26));

    // Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub26 copy;
        copy = sub26;
        TAG2_SUB26_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub26 move;
        move = std::move(sub26);
        TAG2_SUB26_EQ(move);
    }
}

TEST(Tag2Sub26, read_write) {
    const std::string raw = uri;

    OpenPGP::Subpacket::Tag2::Sub26 sub26(raw);
    TAG2_SUB26_EQ(sub26);
    EXPECT_EQ(sub26.raw(), raw);
}

TEST(Tag2Sub26, show) {
    OpenPGP::Subpacket::Tag2::Sub26 sub26;
    EXPECT_NO_THROW(TAG2_SUB26_FILL(sub26));
    EXPECT_NO_THROW(sub26.show());
}

TEST(Tag2Sub26, set_get) {
    OpenPGP::Subpacket::Tag2::Sub26 sub26;
    TAG2_SUB26_FILL(sub26);
    TAG2_SUB26_EQ(sub26);
}

TEST(Tag2Sub26, clone) {
    OpenPGP::Subpacket::Tag2::Sub26 sub26;
    EXPECT_NO_THROW(TAG2_SUB26_FILL(sub26));

    OpenPGP::Subpacket::Sub::Ptr clone = sub26.clone();
    EXPECT_NE(&sub26, clone.get());
    TAG2_SUB26_EQ(*std::static_pointer_cast<OpenPGP::Subpacket::Tag2::Sub26>(clone));
}
