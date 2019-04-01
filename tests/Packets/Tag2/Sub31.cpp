#include <gtest/gtest.h>

#include "Packets/Tag2/Sub31.h"

static const uint8_t pka = OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN;
static const uint8_t hash_alg = OpenPGP::Hash::ID::SHA1;
static const std::string hash(20, '\x00');

static void TAG2_SUB31_FILL(OpenPGP::Subpacket::Tag2::Sub31 & sub31) {
    sub31.set_pka(pka);
    sub31.set_hash_alg(hash_alg);
    sub31.set_hash(hash);
}

#define TAG2_SUB31_EQ(sub31)                        \
    EXPECT_EQ((sub31).get_pka(), pka);              \
    EXPECT_EQ((sub31).get_hash_alg(), hash_alg);    \
    EXPECT_EQ((sub31).get_hash(), hash);            \
    EXPECT_EQ((sub31).valid(true), OpenPGP::Status::SUCCESS);

TEST(Tag2Sub31, Constructor) {
    // Default constructor
    OpenPGP::Subpacket::Tag2::Sub31 sub31;

    EXPECT_EQ(sub31.raw(), std::string("\x00\x00", 2));
    EXPECT_NO_THROW(TAG2_SUB31_FILL(sub31));

    // String Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub31 str(sub31.raw());
        TAG2_SUB31_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub31 copy(sub31);
        TAG2_SUB31_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub31 move(std::move(sub31));
        TAG2_SUB31_EQ(move);
    }
}

TEST(Tag2Sub31, Assignment) {
    OpenPGP::Subpacket::Tag2::Sub31 sub31;
    EXPECT_NO_THROW(TAG2_SUB31_FILL(sub31));

    // Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub31 copy;
        copy = sub31;
        TAG2_SUB31_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub31 move;
        move = std::move(sub31);
        TAG2_SUB31_EQ(move);
    }
}

TEST(Tag2Sub31, read_write) {
    const std::string raw = std::string(1, pka) + std::string(1, hash_alg) + hash;

    OpenPGP::Subpacket::Tag2::Sub31 sub31(raw);
    TAG2_SUB31_EQ(sub31);
    EXPECT_EQ(sub31.raw(), raw);
}

TEST(Tag2Sub31, show) {
    OpenPGP::Subpacket::Tag2::Sub31 sub31;
    EXPECT_NO_THROW(TAG2_SUB31_FILL(sub31));
    EXPECT_NO_THROW(sub31.show());
}

TEST(Tag2Sub31, set_get) {
    OpenPGP::Subpacket::Tag2::Sub31 sub31;
    TAG2_SUB31_FILL(sub31);
    TAG2_SUB31_EQ(sub31);
}

TEST(Tag2Sub31, clone) {
    OpenPGP::Subpacket::Tag2::Sub31 sub31;
    EXPECT_NO_THROW(TAG2_SUB31_FILL(sub31));

    OpenPGP::Subpacket::Sub::Ptr clone = sub31.clone();
    EXPECT_NE(&sub31, clone.get());
    TAG2_SUB31_EQ(*std::static_pointer_cast<OpenPGP::Subpacket::Tag2::Sub31>(clone));
}
