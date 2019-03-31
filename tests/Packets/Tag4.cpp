#include <gtest/gtest.h>

#include "Packets/Tag4.h"

static const uint8_t version = 3;
static const uint8_t type = OpenPGP::Signature_Type::SIGNATURE_OF_A_BINARY_DOCUMENT;
static const uint8_t hash = OpenPGP::Hash::ID::SHA1;
static const uint8_t pka = OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN;
static const std::string keyid("\x00\x01\x02\x03\x04\x05\x06\x07", 8);
static const uint8_t last = 1;

static void TAG4_FILL(OpenPGP::Packet::Tag4 & tag4) {
    tag4.set_version(version);
    tag4.set_type(type);
    tag4.set_hash(hash);
    tag4.set_pka(pka);
    tag4.set_keyid(keyid);
    tag4.set_last(last);
}

#define TAG4_EQ(tag4)                                           \
    EXPECT_EQ((tag4).get_version(), version);                   \
    EXPECT_EQ((tag4).get_type(), type);                         \
    EXPECT_EQ((tag4).get_hash(), hash);                         \
    EXPECT_EQ((tag4).get_pka(), pka);                           \
    EXPECT_EQ((tag4).get_keyid(), keyid);                       \
    EXPECT_EQ((tag4).get_last(), last);                         \
    EXPECT_EQ((tag4).valid(true), OpenPGP::Status::SUCCESS);

TEST(Tag4, Constructor) {
    // Default constructor
    OpenPGP::Packet::Tag4 tag4;

    EXPECT_EQ(tag4.raw(), std::string("\x03\x00\x00\x00\x01", 5));
    EXPECT_NO_THROW(TAG4_FILL(tag4));

    // String Constructor
    {
        OpenPGP::Packet::Tag4 str(tag4.raw());
        TAG4_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Packet::Tag4 copy(tag4);
        TAG4_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Packet::Tag4 move(std::move(tag4));
        TAG4_EQ(move);
    }
}

TEST(Tag4, Assignment) {
    OpenPGP::Packet::Tag4 tag4;
    EXPECT_NO_THROW(TAG4_FILL(tag4));

    // Assignment
    {
        OpenPGP::Packet::Tag4 copy;
        copy = tag4;
        TAG4_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Packet::Tag4 move;
        move = std::move(tag4);
        TAG4_EQ(move);
    }
}

TEST(Tag4, read_write) {
    const std::string raw = std::string(1, version) +
                            std::string(1, type) +
                            std::string(1, hash) +
                            std::string(1, pka) +
                            keyid +
                            std::string(1, last);

    OpenPGP::Packet::Tag4 tag4(raw);
    TAG4_EQ(tag4);
    EXPECT_EQ(tag4.raw(), raw);
}

TEST(Tag4, set_get) {
    OpenPGP::Packet::Tag4 tag4;
    EXPECT_NO_THROW(TAG4_FILL(tag4));
    TAG4_EQ(tag4);
}

TEST(Tag4, clone) {
    OpenPGP::Packet::Tag4 tag4;
    EXPECT_NO_THROW(TAG4_FILL(tag4));

    OpenPGP::Packet::Tag::Ptr clone = tag4.clone();
    EXPECT_NE(&tag4, clone.get());
    TAG4_EQ(*std::static_pointer_cast<OpenPGP::Packet::Tag4>(clone));
}
