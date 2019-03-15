#ifdef GPG_COMPATIBLE

#include <gtest/gtest.h>

#include "Packets/Tag2/Sub33.h"

static const uint8_t version = 0;
static const std::string issuer_fingerprint(20, '\x00');

static void TAG2_SUB33_FILL(OpenPGP::Subpacket::Tag2::Sub33 & sub33) {
    sub33.set_version(version);
    sub33.set_issuer_fingerprint(issuer_fingerprint);
}

#define TAG2_SUB33_EQ(sub33)                                            \
    EXPECT_EQ((sub33).get_version(), version);                          \
    EXPECT_EQ((sub33).get_issuer_fingerprint(), issuer_fingerprint);

TEST(Tag2Sub33, Constructor) {
    // Default constructor
    OpenPGP::Subpacket::Tag2::Sub33 sub33;

    EXPECT_EQ(sub33.raw(), std::string(1, '\x00'));
    EXPECT_NO_THROW(TAG2_SUB33_FILL(sub33));

    // String Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub33 str(sub33.raw());
        TAG2_SUB33_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub33 copy(sub33);
        TAG2_SUB33_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub33 move(std::move(sub33));
        TAG2_SUB33_EQ(move);
    }
}

TEST(Tag2Sub33, Assignment) {
    OpenPGP::Subpacket::Tag2::Sub33 sub33;
    EXPECT_NO_THROW(TAG2_SUB33_FILL(sub33));

    // Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub33 copy;
        copy = sub33;
        TAG2_SUB33_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub33 move;
        move = std::move(sub33);
        TAG2_SUB33_EQ(move);
    }
}

TEST(Tag2Sub33, read_write) {
    const std::string raw = std::string(1, version) + issuer_fingerprint;

    OpenPGP::Subpacket::Tag2::Sub33 sub33(raw);
    TAG2_SUB33_EQ(sub33);
    EXPECT_EQ(sub33.raw(), raw);
}

TEST(Tag2Sub33, set_get) {
    OpenPGP::Subpacket::Tag2::Sub33 sub33;
    TAG2_SUB33_FILL(sub33);
    TAG2_SUB33_EQ(sub33);
}

TEST(Tag2Sub33, clone) {
    OpenPGP::Subpacket::Tag2::Sub33 sub33;
    EXPECT_NO_THROW(TAG2_SUB33_FILL(sub33));

    OpenPGP::Subpacket::Sub::Ptr clone = sub33.clone();
    EXPECT_NE(&sub33, clone.get());
    TAG2_SUB33_EQ(*std::static_pointer_cast<OpenPGP::Subpacket::Tag2::Sub33>(clone));
}

#endif
