#include <gtest/gtest.h>

#include "Packets/Tag5.h"

static const uint8_t version = 4;
static const uint32_t timestamp = 0;
static const uint8_t pka = OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN;
static const OpenPGP::PKA::Values mpi = {0, 0};
static const uint8_t s2k_con = 0;
static const std::string secret = OpenPGP::write_MPI(0) + OpenPGP::write_MPI(0) + OpenPGP::write_MPI(0) + OpenPGP::write_MPI(0);

static void TAG5_FILL(OpenPGP::Packet::Tag5 & tag5) {
    tag5.set_version(version);
    tag5.set_time(timestamp);
    tag5.set_pka(pka);
    tag5.set_mpi(mpi);
    tag5.set_s2k_con(s2k_con);
    tag5.set_secret(secret);
}

#define TAG5_EQ(tag5)                                   \
    EXPECT_EQ((tag5).get_version(), version);           \
    EXPECT_EQ((tag5).get_time(), timestamp);            \
    EXPECT_EQ((tag5).get_pka(), pka);                   \
    EXPECT_EQ((tag5).get_mpi(), mpi);                   \
    EXPECT_EQ((tag5).get_s2k_con(), s2k_con);           \
    EXPECT_EQ((tag5).get_secret(), secret);

TEST(Tag5, Constructor) {
    // Default constructor
    OpenPGP::Packet::Tag5 tag5;

    EXPECT_EQ(tag5.raw(), std::string("\x00\x00\x00\x00\x00\x00\x00\x00\x00", 9));
    EXPECT_NO_THROW(TAG5_FILL(tag5));

    // String Constructor
    {
        OpenPGP::Packet::Tag5 str(tag5.raw());
        TAG5_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Packet::Tag5 copy(tag5);
        TAG5_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Packet::Tag5 move(std::move(tag5));
        TAG5_EQ(move);
    }
}

TEST(Tag5, Assignment) {
    OpenPGP::Packet::Tag5 tag5;
    EXPECT_NO_THROW(TAG5_FILL(tag5));

    // Assignment
    {
        OpenPGP::Packet::Tag5 copy;
        copy = tag5;
        TAG5_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Packet::Tag5 move;
        move = std::move(tag5);
        TAG5_EQ(move);
    }
}

TEST(Tag5, read_write) {
    const std::string raw = std::string(1, version) +
                            unhexlify(makehex(timestamp, 8)) +
                            std::string(1, pka) +
                            OpenPGP::write_MPI(mpi[0]) +
                            OpenPGP::write_MPI(mpi[1]) +
                            std::string(1, s2k_con) +
                            secret;

    OpenPGP::Packet::Tag5 tag5(raw);
    TAG5_EQ(tag5);
    EXPECT_EQ(tag5.raw(), raw);
}

TEST(Tag5, set_get) {
    OpenPGP::Packet::Tag5 tag5;
    EXPECT_NO_THROW(TAG5_FILL(tag5));
    TAG5_EQ(tag5);
}

TEST(Tag5, clone) {
    OpenPGP::Packet::Tag5 tag5;
    OpenPGP::Packet::Tag::Ptr clone = tag5.clone();
    EXPECT_NE(&tag5, clone.get());
    EXPECT_EQ(tag5.raw(), clone -> raw());
}
