#include <gtest/gtest.h>

#include "Misc/s2k.h"

static const uint8_t hash = OpenPGP::Hash::ID::SHA1;
static const std::string salt(8, '\x00');
static const uint8_t count = 0;

TEST(S2K0, Constructor) {
    OpenPGP::S2K::S2K0 s2k0;
    EXPECT_EQ(s2k0.raw(), std::string("\x00\x00", 2));
}

TEST(S2K0, read_write) {
    const std::string specifier("\x00\x00", 2);
    OpenPGP::S2K::S2K0 s2k0;
    std::string::size_type pos = 0;
    s2k0.read(specifier, pos);
    EXPECT_EQ(s2k0.raw(), specifier);
}

TEST(S2K0, set_get) {
    const uint8_t type = OpenPGP::S2K::ID::SIMPLE_S2K;

    OpenPGP::S2K::S2K0 s2k0;
    EXPECT_NO_THROW(s2k0.set_type(type));
    EXPECT_EQ(s2k0.get_type(), type);
    EXPECT_NO_THROW(s2k0.set_hash(hash));
    EXPECT_EQ(s2k0.get_hash(), hash);
}

TEST(S2K0, clone) {
    OpenPGP::S2K::S2K0 s2k0;
    OpenPGP::S2K::S2K::Ptr clone = s2k0.clone();
    EXPECT_NE(&s2k0, clone.get());
    EXPECT_EQ(s2k0.raw(), clone -> raw());
}

TEST(S2K1, Constructor) {
    OpenPGP::S2K::S2K1 s2k1;
    EXPECT_EQ(s2k1.raw(), std::string("\x01\x00", 2));
}

TEST(S2K1, read_write) {
    const std::string specifier = std::string("\x01\x00", 2) + salt;
    OpenPGP::S2K::S2K1 s2k1;
    std::string::size_type pos = 0;
    s2k1.read(specifier, pos);
    EXPECT_EQ(s2k1.raw(), specifier);
}

TEST(S2K1, set_get) {
    const uint8_t type = OpenPGP::S2K::ID::SALTED_S2K;

    OpenPGP::S2K::S2K1 s2k1;
    EXPECT_NO_THROW(s2k1.set_type(type));
    EXPECT_EQ(s2k1.get_type(), type);
    EXPECT_NO_THROW(s2k1.set_hash(hash));
    EXPECT_EQ(s2k1.get_hash(), hash);
    EXPECT_NO_THROW(s2k1.set_salt(salt));
    EXPECT_EQ(s2k1.get_salt(), salt);
}

TEST(S2K1, clone) {
    OpenPGP::S2K::S2K1 s2k1;
    OpenPGP::S2K::S2K::Ptr clone = s2k1.clone();
    EXPECT_NE(&s2k1, clone.get());
    EXPECT_EQ(s2k1.raw(), clone -> raw());
}

TEST(S2K3, Constructor) {
    OpenPGP::S2K::S2K3 s2k3;
    EXPECT_EQ(s2k3.raw(), std::string("\x03\x00\x00", 3));
}

TEST(S2K3, read_write) {
    const std::string specifier = std::string("\x03\x00", 2) + salt + std::string(1, count);
    OpenPGP::S2K::S2K3 s2k3;
    std::string::size_type pos = 0;
    s2k3.read(specifier, pos);
    EXPECT_EQ(s2k3.raw(), specifier);
}

TEST(S2K3, set_get) {
    const uint8_t type = OpenPGP::S2K::ID::ITERATED_AND_SALTED_S2K;

    OpenPGP::S2K::S2K3 s2k3;
    EXPECT_NO_THROW(s2k3.set_type(type));
    EXPECT_EQ(s2k3.get_type(), type);
    EXPECT_NO_THROW(s2k3.set_hash(hash));
    EXPECT_EQ(s2k3.get_hash(), hash);
    EXPECT_NO_THROW(s2k3.set_salt(salt));
    EXPECT_EQ(s2k3.get_salt(), salt);
    EXPECT_NO_THROW(s2k3.set_count(count));
    EXPECT_EQ(s2k3.get_count(), count);
}

TEST(S2K3, clone) {
    OpenPGP::S2K::S2K3 s2k3;
    OpenPGP::S2K::S2K::Ptr clone = s2k3.clone();
    EXPECT_NE(&s2k3, clone.get());
    EXPECT_EQ(s2k3.raw(), clone -> raw());
}
