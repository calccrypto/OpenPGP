#include <gtest/gtest.h>

#include "Packets/Tag2/Sub12.h"

static const uint8_t _class = 0x80;
static const uint8_t pka = OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN;
static const std::string fingerprint(20, '0');

static void TAG2_SUB12_FILL(OpenPGP::Subpacket::Tag2::Sub12 & sub12) {
    sub12.set_class(_class);
    sub12.set_pka(pka);
    sub12.set_fingerprint(fingerprint);
}

#define TAG2_SUB12_EQ(sub12)                            \
    EXPECT_EQ((sub12).get_class(), _class);             \
    EXPECT_EQ((sub12).get_pka(), pka);                  \
    EXPECT_EQ((sub12).get_fingerprint(), fingerprint);

TEST(Tag2Sub12, Constructor) {
    // Default constructor
    OpenPGP::Subpacket::Tag2::Sub12 sub12;

    EXPECT_EQ(sub12.raw(), std::string("\x00\x00", 2));
    EXPECT_NO_THROW(TAG2_SUB12_FILL(sub12));

    // String Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub12 str(sub12.raw());
        TAG2_SUB12_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub12 copy(sub12);
        TAG2_SUB12_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub12 move(std::move(sub12));
        TAG2_SUB12_EQ(move);
    }
}

TEST(Tag2Sub12, Assignment) {
    OpenPGP::Subpacket::Tag2::Sub12 sub12;
    EXPECT_NO_THROW(TAG2_SUB12_FILL(sub12));

    // Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub12 copy;
        copy = sub12;
        TAG2_SUB12_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub12 move;
        move = std::move(sub12);
        TAG2_SUB12_EQ(move);
    }
}

TEST(Tag2Sub12, read_write) {
    const std::string raw = std::string(1, _class) + std::string(1, pka) + fingerprint;

    OpenPGP::Subpacket::Tag2::Sub12 sub12(raw);
    TAG2_SUB12_EQ(sub12);
    EXPECT_EQ(sub12.raw(), raw);
}

TEST(Tag2Sub12, set_get) {
    OpenPGP::Subpacket::Tag2::Sub12 sub12;
    TAG2_SUB12_FILL(sub12);
    TAG2_SUB12_EQ(sub12);
}

TEST(Tag2Sub12, clone) {
    OpenPGP::Subpacket::Tag2::Sub12 sub12;
    EXPECT_NO_THROW(TAG2_SUB12_FILL(sub12));

    OpenPGP::Subpacket::Sub::Ptr clone = sub12.clone();
    EXPECT_NE(&sub12, clone.get());
    TAG2_SUB12_EQ(*std::static_pointer_cast<OpenPGP::Subpacket::Tag2::Sub12>(clone));
}
