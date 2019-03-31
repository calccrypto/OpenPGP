#include <gtest/gtest.h>

#include "Packets/Tag2.h"
#include "Misc/mpi.h"

static const uint8_t version = 4;
static const uint8_t type = OpenPGP::Signature_Type::PRIMARY_KEY_BINDING_SIGNATURE;
static const uint8_t pka = OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN;
static const uint8_t hash = OpenPGP::Hash::ID::SHA1;
static const OpenPGP::PKA::Values mpi = {0};
static const std::string left16(2, '\x00');
static const OpenPGP::Packet::Tag2::Subpackets hashed_subpackets = {std::make_shared <OpenPGP::Subpacket::Tag2::Sub3> ()};
static const OpenPGP::Packet::Tag2::Subpackets unhashed_subpackets = {std::make_shared <OpenPGP::Subpacket::Tag2::Sub4> ()};

static void TAG2_FILL(OpenPGP::Packet::Tag2 & tag2) {
    tag2.set_version(version);
    tag2.set_type(type);
    tag2.set_pka(pka);
    tag2.set_hash(hash);
    tag2.set_left16(left16);
    tag2.set_hashed_subpackets(hashed_subpackets);
    tag2.set_unhashed_subpackets(unhashed_subpackets);
    tag2.set_mpi(mpi);
}

#define TAG2_EQ(tag2)                                                                    \
    EXPECT_EQ((tag2).get_version(), version);                                            \
    EXPECT_EQ((tag2).get_type(), type);                                                  \
    EXPECT_EQ((tag2).get_pka(), pka);                                                    \
    EXPECT_EQ((tag2).get_hash(), hash);                                                  \
    EXPECT_EQ((tag2).get_left16(), left16);                                              \
    const OpenPGP::Packet::Tag2::Subpackets hashed = (tag2).get_hashed_subpackets();     \
    ASSERT_EQ(hashed.size(), hashed_subpackets.size());                                  \
    EXPECT_EQ(hashed[0] -> raw(), hashed_subpackets[0] -> raw());                        \
    const OpenPGP::Packet::Tag2::Subpackets unhashed = (tag2).get_unhashed_subpackets(); \
    ASSERT_EQ(unhashed.size(), unhashed_subpackets.size());                              \
    EXPECT_EQ(unhashed[0] -> raw(), unhashed_subpackets[0] -> raw());                    \
    EXPECT_EQ((tag2).get_mpi(), mpi);                                                    \
    EXPECT_EQ((tag2).valid(true), OpenPGP::Status::SUCCESS);

TEST(Tag2, Constructor) {
    // Default constructor
    OpenPGP::Packet::Tag2 tag2;

    EXPECT_EQ(tag2.raw(), std::string(1, '\x00'));
    EXPECT_NO_THROW(TAG2_FILL(tag2));

    // String Constructor
    {
        OpenPGP::Packet::Tag2 str(tag2.raw());
        TAG2_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Packet::Tag2 copy(tag2);
        TAG2_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Packet::Tag2 move(std::move(tag2));
        TAG2_EQ(move);
    }
}

TEST(Tag2, Assignment) {
    OpenPGP::Packet::Tag2 tag2;
    EXPECT_NO_THROW(TAG2_FILL(tag2));

    // Assignment
    {
        OpenPGP::Packet::Tag2 copy;
        copy = tag2;
        TAG2_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Packet::Tag2 move;
        move = std::move(tag2);
        TAG2_EQ(move);
    }
}

TEST(Tag2, read_write) {
    const std::string hashed_str = hashed_subpackets[0] -> write();
    const std::string unhashed_str = unhashed_subpackets[0] -> write();

    const std::string raw = std::string(1, version) +
        std::string(1, type) +
        std::string(1, pka) +
        std::string(1, hash) +
        unhexlify(makehex(hashed_str.size(), 4)) + hashed_str +
        unhexlify(makehex(unhashed_str.size(), 4)) + unhashed_str +
        std::string(2, '\x00') + OpenPGP::write_MPI(mpi[0]);

    OpenPGP::Packet::Tag2 tag2(raw);
    TAG2_EQ(tag2);
    EXPECT_EQ(tag2.raw(), raw);
}

TEST(Tag2, set_get) {
    OpenPGP::Packet::Tag2 tag2;
    TAG2_FILL(tag2);
    TAG2_EQ(tag2);
}

TEST(Tag2, clone) {
    OpenPGP::Packet::Tag2 tag2;
    EXPECT_NO_THROW(TAG2_FILL(tag2));

    OpenPGP::Packet::Tag::Ptr clone = tag2.clone();
    EXPECT_NE(&tag2, clone.get());
    TAG2_EQ(*std::static_pointer_cast<OpenPGP::Packet::Tag2>(clone));
}
