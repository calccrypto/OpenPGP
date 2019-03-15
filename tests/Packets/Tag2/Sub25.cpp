#include <gtest/gtest.h>

#include "Packets/Tag2/Sub25.h"

static const bool primary = false;

static void TAG2_SUB25_FILL(OpenPGP::Subpacket::Tag2::Sub25 & sub25) {
    sub25.set_primary(primary);
}

#define TAG2_SUB25_EQ(sub25)                    \
    EXPECT_EQ((sub25).get_primary(), primary);

TEST(Tag2Sub25, Constructor) {
    // Default constructor
    OpenPGP::Subpacket::Tag2::Sub25 sub25;

    EXPECT_EQ(sub25.raw(), std::string(1, '\x00'));
    EXPECT_NO_THROW(TAG2_SUB25_FILL(sub25));

    // String Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub25 str(sub25.raw());
        TAG2_SUB25_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub25 copy(sub25);
        TAG2_SUB25_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub25 move(std::move(sub25));
        TAG2_SUB25_EQ(move);
    }
}

TEST(Tag2Sub25, Assignment) {
    OpenPGP::Subpacket::Tag2::Sub25 sub25;
    EXPECT_NO_THROW(TAG2_SUB25_FILL(sub25));

    // Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub25 copy;
        copy = sub25;
        TAG2_SUB25_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub25 move;
        move = std::move(sub25);
        TAG2_SUB25_EQ(move);
    }
}

TEST(Tag2Sub25, read_write) {
    const std::string raw(1, primary);

    OpenPGP::Subpacket::Tag2::Sub25 sub25(raw);
    TAG2_SUB25_EQ(sub25);
    EXPECT_EQ(sub25.raw(), raw);
}

TEST(Tag2Sub25, set_get) {
    OpenPGP::Subpacket::Tag2::Sub25 sub25;
    TAG2_SUB25_FILL(sub25);
    TAG2_SUB25_EQ(sub25);
}

TEST(Tag2Sub25, clone) {
    OpenPGP::Subpacket::Tag2::Sub25 sub25;
    EXPECT_NO_THROW(TAG2_SUB25_FILL(sub25));

    OpenPGP::Subpacket::Sub::Ptr clone = sub25.clone();
    EXPECT_NE(&sub25, clone.get());
    TAG2_SUB25_EQ(*std::static_pointer_cast<OpenPGP::Subpacket::Tag2::Sub25>(clone));
}
