#include <gtest/gtest.h>

#include "Packets/Key.h"

static const uint8_t version = 4;
static const uint8_t timestamp = 0;
static const uint8_t pka = OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN;
static const OpenPGP::PKA::Values mpi = {0, 0};

static void KEY_FILL(OpenPGP::Packet::Key & key) {
    key.set_version(version);
    key.set_time(timestamp);
    key.set_pka(pka);
    key.set_mpi(mpi);
}

#define KEY_EQ(key)                                \
    EXPECT_EQ((key).get_version(), version);       \
    EXPECT_EQ((key).get_time(), timestamp);        \
    EXPECT_EQ((key).get_pka(), pka);               \
    EXPECT_EQ((key).get_mpi(), mpi);

TEST(KeyTag, Constructor) {
    // Default constructor
    OpenPGP::Packet::Key key;

    EXPECT_EQ(key.raw(), std::string("\x00\x00\x00\x00\x00\x00\x00", 8));
    EXPECT_NO_THROW(KEY_FILL(key));

    // String Constructor
    {
        OpenPGP::Packet::Key str(key.raw());
        KEY_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Packet::Key copy(key);
        KEY_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Packet::Key move(std::move(key));
        KEY_EQ(move);
    }
}

TEST(KeyTag, Assignment) {
    OpenPGP::Packet::Key key;
    EXPECT_NO_THROW(KEY_FILL(key));

    // Assignment
    {
        OpenPGP::Packet::Key copy;
        copy = key;
        KEY_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Packet::Key move;
        move = std::move(key);
        KEY_EQ(move);
    }
}

TEST(KeyTag, read_write) {
    const std::string raw = std::string(1, version) +
                            unhexlify(makehex(timestamp, 8)) +
                            std::string(1, pka) +
                            OpenPGP::write_MPI(mpi[0]) +
                            OpenPGP::write_MPI(mpi[1]);

    OpenPGP::Packet::Key key(raw);
    KEY_EQ(key);
    EXPECT_EQ(key.raw(), raw);
}

TEST(KeyTag, set_get) {
    OpenPGP::Packet::Key key;
    EXPECT_NO_THROW(KEY_FILL(key));
    KEY_EQ(key);
}

TEST(KeyTag, clone) {
    OpenPGP::Packet::Key key;
    EXPECT_NO_THROW(KEY_FILL(key));

    OpenPGP::Packet::Tag::Ptr clone = key.clone();
    EXPECT_NE(&key, clone.get());
    KEY_EQ(*std::static_pointer_cast<OpenPGP::Packet::Key>(clone));
}
