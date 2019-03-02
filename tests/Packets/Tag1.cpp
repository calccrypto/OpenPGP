#include <gtest/gtest.h>

#include "Packets/Tag1.h"

static const uint8_t version = 3;
static const std::string keyid("\x00\x01\x02\x03\x04\x05\x06\x07", 8);
static const uint8_t pka = OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN;
static const OpenPGP::PKA::Values mpi = {0};

static void TAG1_FILL(OpenPGP::Packet::Tag1 & tag1) {
    tag1.set_version(version);
    tag1.set_keyid(keyid);
    tag1.set_pka(pka);
    tag1.set_mpi(mpi);
}

#define TAG1_EQ(tag1)                           \
    EXPECT_EQ((tag1).get_version(), version);   \
    EXPECT_EQ((tag1).get_keyid(), keyid);       \
    EXPECT_EQ((tag1).get_pka(), pka);           \
    EXPECT_EQ((tag1).get_mpi(), mpi);

TEST(Tag1, Constructor) {
    // Default constructor
    OpenPGP::Packet::Tag1 tag1;

    EXPECT_EQ(tag1.raw(), std::string("\x03\x00", 2));
    EXPECT_NO_THROW(TAG1_FILL(tag1));

    // String Constructor
    {
        OpenPGP::Packet::Tag1 str(tag1.raw());
        TAG1_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Packet::Tag1 copy(tag1);
        TAG1_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Packet::Tag1 move(std::move(tag1));
        TAG1_EQ(move);
    }
}

TEST(Tag1, Assignment) {
    OpenPGP::Packet::Tag1 tag1;
    EXPECT_NO_THROW(TAG1_FILL(tag1));

    // Assignment
    {
        OpenPGP::Packet::Tag1 copy;
        copy = tag1;
        TAG1_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Packet::Tag1 move;
        move = std::move(tag1);
        TAG1_EQ(move);
    }
}

TEST(Tag1, read_write) {
    // RSA
    {
        const std::string rsa_mpi = OpenPGP::write_MPI(mpi[0]);
        const std::string raw = std::string(1, version) + keyid + std::string(1, pka) + rsa_mpi;

        OpenPGP::Packet::Tag1 tag1(raw);
        TAG1_EQ(tag1);

        EXPECT_EQ(tag1.raw(), raw);
    }

    // DSA
    {
        const uint8_t dsa_pka = OpenPGP::PKA::ID::DSA;
        const std::string dsa_mpi = OpenPGP::write_MPI(0) + OpenPGP::write_MPI(1);
        const std::string raw = std::string(1, version) + keyid + std::string(1, dsa_pka) + dsa_mpi;

        OpenPGP::Packet::Tag1 tag1(raw);
        EXPECT_EQ(tag1.get_version(), version);
        EXPECT_EQ(tag1.get_keyid(), keyid);
        EXPECT_EQ(tag1.get_pka(), dsa_pka);
        EXPECT_EQ(tag1.get_mpi(), OpenPGP::PKA::Values({0, 1}));

        EXPECT_EQ(tag1.raw(), raw);
    }
}

TEST(Tag1, set_get) {
    OpenPGP::Packet::Tag1 tag1;
    EXPECT_NO_THROW(TAG1_FILL(tag1));
    TAG1_EQ(tag1);
}

TEST(Tag1, clone) {
    OpenPGP::Packet::Tag1 tag1;
    EXPECT_NO_THROW(TAG1_FILL(tag1));

    OpenPGP::Packet::Tag::Ptr clone = tag1.clone();
    EXPECT_NE(&tag1, clone.get());
    TAG1_EQ(*std::static_pointer_cast<OpenPGP::Packet::Tag1>(clone));
}
