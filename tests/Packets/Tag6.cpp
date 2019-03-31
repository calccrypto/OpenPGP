#include <gtest/gtest.h>

#include "Packets/Tag6.h"

static const uint8_t version = 4;
static const uint32_t timestamp = 0;
static const uint8_t pka = OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN;
static const OpenPGP::PKA::Values mpi = {0, 0};

static void TAG6_FILL(OpenPGP::Packet::Tag6 & tag6) {
    tag6.set_version(version);
    tag6.set_time(timestamp);
    tag6.set_pka(pka);
    tag6.set_mpi(mpi);
}

#define TAG6_EQ(tag6)                                           \
    EXPECT_EQ((tag6).get_version(), version);                   \
    EXPECT_EQ((tag6).get_time(), timestamp);                    \
    EXPECT_EQ((tag6).get_pka(), pka);                           \
    EXPECT_EQ((tag6).get_mpi(), mpi);                           \
    EXPECT_EQ((tag6).valid(true), OpenPGP::Status::SUCCESS);

TEST(Tag6, Constructor) {
    // Default constructor
    OpenPGP::Packet::Tag6 tag6;

    EXPECT_EQ(tag6.raw(), std::string("\x00\x00\x00\x00\x00\x00\x00\x00", 8));
    EXPECT_NO_THROW(TAG6_FILL(tag6));

    // String Constructor
    {
        OpenPGP::Packet::Tag6 str(tag6.raw());
        TAG6_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Packet::Tag6 copy(tag6);
        TAG6_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Packet::Tag6 move(std::move(tag6));
        TAG6_EQ(move);
    }
}

TEST(Tag6, Assignment) {
    OpenPGP::Packet::Tag6 tag6;
    EXPECT_NO_THROW(TAG6_FILL(tag6));

    // Assignment
    {
        OpenPGP::Packet::Tag6 copy;
        copy = tag6;
        TAG6_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Packet::Tag6 move;
        move = std::move(tag6);
        TAG6_EQ(move);
    }
}

TEST(Tag6, read_write) {
    const std::string raw = std::string(1, version) +
                            unhexlify(makehex(timestamp, 8)) +
                            std::string(1, pka) +
                            OpenPGP::write_MPI(mpi[0]) +
                            OpenPGP::write_MPI(mpi[1]);

    OpenPGP::Packet::Tag6 tag6(raw);
    TAG6_EQ(tag6);
    EXPECT_EQ(tag6.raw(), raw);
}

TEST(Tag6, set_get) {
    OpenPGP::Packet::Tag6 tag6;
    EXPECT_NO_THROW(TAG6_FILL(tag6));
    TAG6_EQ(tag6);
}

TEST(Tag6, clone) {
    OpenPGP::Packet::Tag6 tag6;
    OpenPGP::Packet::Tag::Ptr clone = tag6.clone();
    EXPECT_NE(&tag6, clone.get());
    EXPECT_EQ(tag6.raw(), clone -> raw());
}
