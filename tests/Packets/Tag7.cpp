#include <gtest/gtest.h>

#include "Packets/Tag7.h"

static const uint8_t version = 4;
static const uint32_t timestamp = 0;
static const uint8_t pka = OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN;
static const OpenPGP::PKA::Values mpi = {0, 0};
static const uint8_t s2k_con = 0;
static const std::string secret = OpenPGP::write_MPI(0) + OpenPGP::write_MPI(0) + OpenPGP::write_MPI(0) + OpenPGP::write_MPI(0);

static void TAG7_FILL(OpenPGP::Packet::Tag7 & tag7) {
    tag7.set_version(version);
    tag7.set_time(timestamp);
    tag7.set_pka(pka);
    tag7.set_mpi(mpi);
    tag7.set_s2k_con(s2k_con);
    tag7.set_secret(secret);
}

#define TAG7_EQ(tag7)                                           \
    EXPECT_EQ((tag7).get_version(), version);                   \
    EXPECT_EQ((tag7).get_time(), timestamp);                    \
    EXPECT_EQ((tag7).get_pka(), pka);                           \
    EXPECT_EQ((tag7).get_mpi(), mpi);                           \
    EXPECT_EQ((tag7).get_s2k_con(), s2k_con);                   \
    EXPECT_EQ((tag7).get_secret(), secret);                     \
    EXPECT_EQ((tag7).valid(true), OpenPGP::Status::SUCCESS);

TEST(Tag7, Constructor) {
    // Default constructor
    OpenPGP::Packet::Tag7 tag7;

    EXPECT_EQ(tag7.raw(), std::string("\x00\x00\x00\x00\x00\x00\x00\x00\x00", 9));
    EXPECT_NO_THROW(TAG7_FILL(tag7));

    // String Constructor
    {
        OpenPGP::Packet::Tag7 str(tag7.raw());
        TAG7_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Packet::Tag7 copy(tag7);
        TAG7_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Packet::Tag7 move(std::move(tag7));
        TAG7_EQ(move);
    }
}

TEST(Tag7, Assignment) {
    OpenPGP::Packet::Tag7 tag7;
    EXPECT_NO_THROW(TAG7_FILL(tag7));

    // Assignment
    {
        OpenPGP::Packet::Tag7 copy;
        copy = tag7;
        TAG7_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Packet::Tag7 move;
        move = std::move(tag7);
        TAG7_EQ(move);
    }
}

TEST(Tag7, read_write) {
    const std::string raw = std::string(1, version) +
                            unhexlify(makehex(timestamp, 8)) +
                            std::string(1, pka) +
                            OpenPGP::write_MPI(mpi[0]) +
                            OpenPGP::write_MPI(mpi[1]) +
                            std::string(1, s2k_con) +
                            secret;

    OpenPGP::Packet::Tag7 tag7(raw);
    TAG7_EQ(tag7);
    EXPECT_EQ(tag7.raw(), raw);
}

TEST(Tag7, show) {
    OpenPGP::Packet::Tag7 tag7;
    EXPECT_NO_THROW(TAG7_FILL(tag7));
    EXPECT_NO_THROW(tag7.show());
}

TEST(Tag7, set_get) {
    OpenPGP::Packet::Tag7 tag7;
    EXPECT_NO_THROW(TAG7_FILL(tag7));
    TAG7_EQ(tag7);
}

TEST(Tag7, clone) {
    OpenPGP::Packet::Tag7 tag7;
    OpenPGP::Packet::Tag::Ptr clone = tag7.clone();
    EXPECT_NE(&tag7, clone.get());
    EXPECT_EQ(tag7.raw(), clone -> raw());
}
