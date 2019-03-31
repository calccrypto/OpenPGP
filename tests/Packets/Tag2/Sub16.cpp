#include <gtest/gtest.h>

#include "Packets/Tag2/Sub16.h"

static const std::string keyid("\x00\x01\x02\x03\x04\x05\x06\x07", 8);

static void TAG2_SUB16_FILL(OpenPGP::Subpacket::Tag2::Sub16 & sub16) {
    sub16.set_keyid(keyid);
}

#define TAG2_SUB16_EQ(sub16)                                    \
    EXPECT_EQ((sub16).get_keyid(), keyid);                      \
    EXPECT_EQ((sub16).valid(true), OpenPGP::Status::SUCCESS);

TEST(Tag2Sub16, Constructor) {
    // Default constructor
    OpenPGP::Subpacket::Tag2::Sub16 sub16;

    EXPECT_EQ(sub16.raw(), "");
    EXPECT_NO_THROW(TAG2_SUB16_FILL(sub16));

    // String Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub16 str(sub16.raw());
        TAG2_SUB16_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub16 copy(sub16);
        TAG2_SUB16_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub16 move(std::move(sub16));
        TAG2_SUB16_EQ(move);
    }
}

TEST(Tag2Sub16, Assignment) {
    OpenPGP::Subpacket::Tag2::Sub16 sub16;
    EXPECT_NO_THROW(TAG2_SUB16_FILL(sub16));

    // Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub16 copy;
        copy = sub16;
        TAG2_SUB16_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub16 move;
        move = std::move(sub16);
        TAG2_SUB16_EQ(move);
    }
}

TEST(Tag2Sub16, read_write) {
    const std::string raw = keyid;

    OpenPGP::Subpacket::Tag2::Sub16 sub16(raw);
    TAG2_SUB16_EQ(sub16);
    EXPECT_EQ(sub16.raw(), raw);
}

TEST(Tag2Sub16, set_get) {
    OpenPGP::Subpacket::Tag2::Sub16 sub16;
    TAG2_SUB16_FILL(sub16);
    TAG2_SUB16_EQ(sub16);
}

TEST(Tag2Sub16, clone) {
    OpenPGP::Subpacket::Tag2::Sub16 sub16;
    EXPECT_NO_THROW(TAG2_SUB16_FILL(sub16));

    OpenPGP::Subpacket::Sub::Ptr clone = sub16.clone();
    EXPECT_NE(&sub16, clone.get());
    TAG2_SUB16_EQ(*std::static_pointer_cast<OpenPGP::Subpacket::Tag2::Sub16>(clone));
}
