#include <gtest/gtest.h>

#include "Packets/Tag14.h"

static const uint8_t version = 4;
static const uint32_t timestamp = 0;
static const uint8_t pka = OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN;
static const OpenPGP::PKA::Values mpi = {0, 0};

static void TAG14_FILL(OpenPGP::Packet::Tag14 & tag14) {
    tag14.set_version(version);
    tag14.set_time(timestamp);
    tag14.set_pka(pka);
    tag14.set_mpi(mpi);
}

#define TAG14_EQ(tag14)                                       \
    EXPECT_EQ((tag14).get_version(), version);                \
    EXPECT_EQ((tag14).get_time(), timestamp);                 \
    EXPECT_EQ((tag14).get_pka(), pka);                        \
    EXPECT_EQ((tag14).get_mpi(), mpi);                        \
    EXPECT_EQ((tag14).valid(true), OpenPGP::Status::SUCCESS);

TEST(Tag14, Constructor) {
    // Default constructor
    OpenPGP::Packet::Tag14 tag14;

    EXPECT_EQ(tag14.raw(), std::string("\x00\x00\x00\x00\x00\x00\x00\x00", 8));
    EXPECT_NO_THROW(TAG14_FILL(tag14));

    // String Constructor
    {
        OpenPGP::Packet::Tag14 str(tag14.raw());
        TAG14_EQ(str);
   }

    // Copy Constructor
    {
        OpenPGP::Packet::Tag14 copy(tag14);
        TAG14_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Packet::Tag14 move(std::move(tag14));
        TAG14_EQ(move);
    }
}

TEST(Tag14, Assignment) {
    OpenPGP::Packet::Tag14 tag14;
    EXPECT_NO_THROW(TAG14_FILL(tag14));

    // Assignment
    {
        OpenPGP::Packet::Tag14 copy;
        copy = tag14;
        TAG14_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Packet::Tag14 move;
        move = std::move(tag14);
        TAG14_EQ(move);
    }
}

TEST(Tag14, read_write) {
    const std::string raw = std::string(1, version) +
                            unhexlify(makehex(timestamp, 8)) +
                            std::string(1, pka) +
                            OpenPGP::write_MPI(mpi[0]) +
                            OpenPGP::write_MPI(mpi[1]);

    OpenPGP::Packet::Tag14 tag14(raw);
    TAG14_EQ(tag14);
    EXPECT_EQ(tag14.raw(), raw);
}

TEST(Tag14, show) {
    OpenPGP::Packet::Tag14 tag14;
    EXPECT_NO_THROW(TAG14_FILL(tag14));
    EXPECT_NO_THROW(tag14.show());
}

TEST(Tag14, set_get) {
    OpenPGP::Packet::Tag14 tag14;
    EXPECT_NO_THROW(TAG14_FILL(tag14));
    TAG14_EQ(tag14);
}

TEST(Tag14, clone) {
    OpenPGP::Packet::Tag14 tag14;
    OpenPGP::Packet::Tag::Ptr clone = tag14.clone();
    EXPECT_NE(&tag14, clone.get());
    EXPECT_EQ(tag14.raw(), clone -> raw());
}
