#include <gtest/gtest.h>

#include "Packets/Tag3.h"

static const uint8_t version = 4;
static const uint8_t sym = OpenPGP::Sym::ID::AES128;
static const std::string esk("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\0e\x0f", 16);
static const OpenPGP::S2K::S2K1::Ptr s2k = std::make_shared <OpenPGP::S2K::S2K1> (std::string(1, OpenPGP::S2K::ID::SALTED_S2K) +
                                                                                  std::string(1, OpenPGP::Hash::ID::SHA1) +
                                                                                  std::string(8, '\x00'));

static void TAG3_FILL(OpenPGP::Packet::Tag3 & tag3) {
    tag3.set_version(version);
    tag3.set_sym(sym);
    tag3.set_s2k(s2k);
    tag3.set_esk(esk);
}

#define TAG3_EQ(tag3)                                   \
    EXPECT_EQ((tag3).get_version(), version);           \
    EXPECT_EQ((tag3).get_sym(), sym);                   \
    EXPECT_EQ((tag3).get_s2k() -> raw(), s2k -> raw()); \
    EXPECT_EQ(*((tag3).get_esk()), esk);

TEST(Tag3, Constructor) {
    // Default constructor
    OpenPGP::Packet::Tag3 tag3;

    EXPECT_EQ(tag3.raw(), std::string("\x04\x00", 2));
    EXPECT_NO_THROW(TAG3_FILL(tag3));

    // String Constructor
    {
        OpenPGP::Packet::Tag3 str(tag3.raw());
        TAG3_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Packet::Tag3 copy(tag3);
        TAG3_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Packet::Tag3 move(std::move(tag3));
        TAG3_EQ(move);
    }
}

TEST(Tag3, Assignment) {
    OpenPGP::Packet::Tag3 tag3;
    EXPECT_NO_THROW(TAG3_FILL(tag3));

    // Assignment
    {
        OpenPGP::Packet::Tag3 copy;
        copy = tag3;
        TAG3_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Packet::Tag3 move;
        move = std::move(tag3);
        TAG3_EQ(move);
    }
}

TEST(Tag3, read_write) {
    const std::string raw = std::string(1, version) + std::string(1, sym) + s2k -> raw() + esk;

    OpenPGP::Packet::Tag3 tag3(raw);
    TAG3_EQ(tag3);
    EXPECT_EQ(tag3.raw(), raw);
}

TEST(Tag3, set_get) {
    OpenPGP::Packet::Tag3 tag3;
    TAG3_FILL(tag3);
    TAG3_EQ(tag3);
}

TEST(Tag3, clone) {
    OpenPGP::Packet::Tag3 tag3;
    EXPECT_NO_THROW(TAG3_FILL(tag3));

    OpenPGP::Packet::Tag::Ptr clone = tag3.clone();
    EXPECT_NE(&tag3, clone.get());
    TAG3_EQ(*std::static_pointer_cast<OpenPGP::Packet::Tag3>(clone));
}
