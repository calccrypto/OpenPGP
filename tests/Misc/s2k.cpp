#include <gtest/gtest.h>

#include "Misc/s2k.h"

static const uint8_t hash = OpenPGP::Hash::ID::SHA1;
static const std::string salt(8, '\x00');
static const uint8_t count = 0;
static const std::string key("\x00\x01\x02\x03\x04\x05\x06\x07", 8);

TEST(S2K0, Constructor) {
    OpenPGP::S2K::S2K0 s2k0;
    EXPECT_EQ(s2k0.raw(), std::string("\x00\x00", 2));
}

TEST(S2K0, read_write) {
    const std::string specifier = std::string("\x00", 1) + std::string(1, hash);
    OpenPGP::S2K::S2K0 s2k0(specifier);
    EXPECT_EQ(s2k0.raw(), specifier);
    EXPECT_EQ(s2k0.valid(), OpenPGP::Status::SUCCESS);
}

TEST(S2K0, show) {
    OpenPGP::S2K::S2K0 s2k0;
    EXPECT_NO_THROW(s2k0.show());
}

TEST(S2K0, set_get) {
    const uint8_t type = OpenPGP::S2K::ID::SIMPLE_S2K;

    OpenPGP::S2K::S2K0 s2k0;
    EXPECT_NO_THROW(s2k0.set_type(type));
    EXPECT_EQ(s2k0.get_type(), type);
    EXPECT_NO_THROW(s2k0.set_hash(hash));
    EXPECT_EQ(s2k0.get_hash(), hash);
    EXPECT_EQ(s2k0.valid(), OpenPGP::Status::SUCCESS);
}

// Only tests output size, not correctness of output
TEST(S2K0, run_output_length) {
    OpenPGP::S2K::S2K0 s2k0;
    for(std::pair <const uint8_t, std::size_t> const & hl : OpenPGP::Hash::LENGTH) {
        s2k0.set_hash(hl.first);
        for(std::pair <const uint8_t, std::size_t> const & sl : OpenPGP::Sym::KEY_LENGTH) {
            const std::size_t kl_octets = sl.second >> 3;
            EXPECT_EQ(s2k0.run(key, kl_octets).size(), kl_octets);
        }
    }
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
    const std::string specifier = std::string("\x01", 1) + std::string(1, hash) + salt;
    OpenPGP::S2K::S2K1 s2k1(specifier);
    EXPECT_EQ(s2k1.raw(), specifier);
    EXPECT_EQ(s2k1.valid(), OpenPGP::Status::SUCCESS);
}

TEST(S2K1, show) {
    OpenPGP::S2K::S2K1 s2k1;
    EXPECT_NO_THROW(s2k1.show());
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
    EXPECT_EQ(s2k1.valid(), OpenPGP::Status::SUCCESS);
}

// Only tests output size, not correctness of output
TEST(S2K1, run_output_length) {
    OpenPGP::S2K::S2K1 s2k1;
    s2k1.set_salt(key);
    for(std::pair <const uint8_t, std::size_t> const & hl : OpenPGP::Hash::LENGTH) {
        s2k1.set_hash(hl.first);
        for(std::pair <const uint8_t, std::size_t> const & sl : OpenPGP::Sym::KEY_LENGTH) {
            const std::size_t kl_octets = sl.second >> 3;
            EXPECT_EQ(s2k1.run(key, kl_octets).size(), kl_octets);
        }
    }
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
    const std::string specifier = std::string("\x03", 1) + std::string(1, hash) + salt + std::string(1, count);
    OpenPGP::S2K::S2K3 s2k3(specifier);
    EXPECT_EQ(s2k3.raw(), specifier);
    EXPECT_EQ(s2k3.valid(), OpenPGP::Status::SUCCESS);
}

TEST(S2K3, show) {
    OpenPGP::S2K::S2K3 s2k3;
    EXPECT_NO_THROW(s2k3.show());
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
    EXPECT_EQ(s2k3.valid(), OpenPGP::Status::SUCCESS);
}

// Only tests output size, not correctness of output
TEST(S2K3, run_output_length) {
    OpenPGP::S2K::S2K3 s2k3;
    s2k3.set_salt(key);
    s2k3.set_count(96);
    for(std::pair <const uint8_t, std::size_t> const & hl : OpenPGP::Hash::LENGTH) {
        s2k3.set_hash(hl.first);
        for(std::pair <const uint8_t, std::size_t> const & sl : OpenPGP::Sym::KEY_LENGTH) {
            const std::size_t kl_octets = sl.second >> 3;
            EXPECT_EQ(s2k3.run(key, kl_octets).size(), kl_octets);
        }
    }
}

TEST(S2K3, clone) {
    OpenPGP::S2K::S2K3 s2k3;
    OpenPGP::S2K::S2K::Ptr clone = s2k3.clone();
    EXPECT_NE(&s2k3, clone.get());
    EXPECT_EQ(s2k3.raw(), clone -> raw());
}
