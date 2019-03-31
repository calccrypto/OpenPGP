#include <gtest/gtest.h>

#include "Packets/Tag2/Sub11.h"

static const std::string psa = "";

static void TAG2_SUB11_FILL(OpenPGP::Subpacket::Tag2::Sub11 & sub11) {
    sub11.set_psa(psa);
}

#define TAG2_SUB11_EQ(sub11)                      \
    EXPECT_EQ((sub11).get_psa(), psa);            \
    EXPECT_EQ((sub11).valid(true), OpenPGP::Status::SUCCESS);

TEST(Tag2Sub11, Constructor) {
    // Default constructor
    OpenPGP::Subpacket::Tag2::Sub11 sub11;

    EXPECT_EQ(sub11.raw(), psa);
    EXPECT_NO_THROW(TAG2_SUB11_FILL(sub11));

    // String Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub11 str(sub11.raw());
        TAG2_SUB11_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub11 copy(sub11);
        TAG2_SUB11_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub11 move(std::move(sub11));
        TAG2_SUB11_EQ(move);
    }
}

TEST(Tag2Sub11, Assignment) {
    OpenPGP::Subpacket::Tag2::Sub11 sub11;
    EXPECT_NO_THROW(TAG2_SUB11_FILL(sub11));

    // Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub11 copy;
        copy = sub11;
        TAG2_SUB11_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub11 move;
        move = std::move(sub11);
        TAG2_SUB11_EQ(move);
    }
}

TEST(Tag2Sub11, read_write) {
    const std::string raw = psa;

    OpenPGP::Subpacket::Tag2::Sub11 sub11(raw);
    TAG2_SUB11_EQ(sub11);
    EXPECT_EQ(sub11.raw(), raw);
}

TEST(Tag2Sub11, set_get) {
    OpenPGP::Subpacket::Tag2::Sub11 sub11;
    TAG2_SUB11_FILL(sub11);
    TAG2_SUB11_EQ(sub11);
}

TEST(Tag2Sub11, clone) {
    OpenPGP::Subpacket::Tag2::Sub11 sub11;
    EXPECT_NO_THROW(TAG2_SUB11_FILL(sub11));

    OpenPGP::Subpacket::Sub::Ptr clone = sub11.clone();
    EXPECT_NE(&sub11, clone.get());
    TAG2_SUB11_EQ(*std::static_pointer_cast<OpenPGP::Subpacket::Tag2::Sub11>(clone));
}
