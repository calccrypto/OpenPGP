#include <gtest/gtest.h>

#include "Packets/Tag2/Sub22.h"

static const std::string pca = std::string(1, OpenPGP::Compression::ID::ZIP);

static void TAG2_SUB22_FILL(OpenPGP::Subpacket::Tag2::Sub22 & sub22) {
    sub22.set_pca(pca);
}

#define TAG2_SUB22_EQ(sub22)                    \
    EXPECT_EQ((sub22).get_pca(), pca);

TEST(Tag2Sub22, Constructor) {
    // Default constructor
    OpenPGP::Subpacket::Tag2::Sub22 sub22;

    EXPECT_EQ(sub22.raw(), "");
    EXPECT_NO_THROW(TAG2_SUB22_FILL(sub22));

    // String Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub22 str(sub22.raw());
        TAG2_SUB22_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub22 copy(sub22);
        TAG2_SUB22_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub22 move(std::move(sub22));
        TAG2_SUB22_EQ(move);
    }
}

TEST(Tag2Sub22, Assignment) {
    OpenPGP::Subpacket::Tag2::Sub22 sub22;
    EXPECT_NO_THROW(TAG2_SUB22_FILL(sub22));

    // Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub22 copy;
        copy = sub22;
        TAG2_SUB22_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub22 move;
        move = std::move(sub22);
        TAG2_SUB22_EQ(move);
    }
}

TEST(Tag2Sub22, read_write) {
    const std::string raw = pca;

    OpenPGP::Subpacket::Tag2::Sub22 sub22(raw);
    TAG2_SUB22_EQ(sub22);
    EXPECT_EQ(sub22.raw(), raw);
}

TEST(Tag2Sub22, set_get) {
    OpenPGP::Subpacket::Tag2::Sub22 sub22;
    TAG2_SUB22_FILL(sub22);
    TAG2_SUB22_EQ(sub22);
}

TEST(Tag2Sub22, clone) {
    OpenPGP::Subpacket::Tag2::Sub22 sub22;
    EXPECT_NO_THROW(TAG2_SUB22_FILL(sub22));

    OpenPGP::Subpacket::Sub::Ptr clone = sub22.clone();
    EXPECT_NE(&sub22, clone.get());
    TAG2_SUB22_EQ(*std::static_pointer_cast<OpenPGP::Subpacket::Tag2::Sub22>(clone));
}
