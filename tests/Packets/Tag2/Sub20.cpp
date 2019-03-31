#include <gtest/gtest.h>

#include "Packets/Tag2/Sub20.h"

static const std::string flags = std::string(1, OpenPGP::Subpacket::Tag2::Notation::HUMAN_READABLE) + std::string(3, OpenPGP::Subpacket::Tag2::Notation::UNDEFINED);
static const std::string m = "";
static const std::string n = "";

static void TAG2_SUB20_FILL(OpenPGP::Subpacket::Tag2::Sub20 & sub20) {
    sub20.set_flags(flags);
    sub20.set_m(m);
    sub20.set_n(n);
}

#define TAG2_SUB20_EQ(sub20)                                            \
    EXPECT_EQ((sub20).get_flags(), flags);                              \
    EXPECT_EQ((sub20).get_m(), m);                                      \
    EXPECT_EQ((sub20).get_n(), n);                                      \
    EXPECT_EQ((sub20).valid(true), OpenPGP::Status::SUCCESS);

TEST(Tag2Sub20, Constructor) {
    // Default constructor
    OpenPGP::Subpacket::Tag2::Sub20 sub20;

    EXPECT_EQ(sub20.raw(), std::string(4, '\x00'));
    EXPECT_NO_THROW(TAG2_SUB20_FILL(sub20));

    // String Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub20 str(sub20.raw());
        TAG2_SUB20_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub20 copy(sub20);
        TAG2_SUB20_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Subpacket::Tag2::Sub20 move(std::move(sub20));
        TAG2_SUB20_EQ(move);
    }
}

TEST(Tag2Sub20, Assignment) {
    OpenPGP::Subpacket::Tag2::Sub20 sub20;
    EXPECT_NO_THROW(TAG2_SUB20_FILL(sub20));

    // Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub20 copy;
        copy = sub20;
        TAG2_SUB20_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Subpacket::Tag2::Sub20 move;
        move = std::move(sub20);
        TAG2_SUB20_EQ(move);
    }
}

TEST(Tag2Sub20, read_write) {
    const std::string raw = flags + unhexlify(makehex(m.size(), 4)) + unhexlify(makehex(n.size(), 4)) + m + n;

    OpenPGP::Subpacket::Tag2::Sub20 sub20(raw);
    TAG2_SUB20_EQ(sub20);
    EXPECT_EQ(sub20.raw(), raw);
}

TEST(Tag2Sub20, set_get) {
    OpenPGP::Subpacket::Tag2::Sub20 sub20;
    TAG2_SUB20_FILL(sub20);
    TAG2_SUB20_EQ(sub20);
}

TEST(Tag2Sub20, clone) {
    OpenPGP::Subpacket::Tag2::Sub20 sub20;
    EXPECT_NO_THROW(TAG2_SUB20_FILL(sub20));

    OpenPGP::Subpacket::Sub::Ptr clone = sub20.clone();
    EXPECT_NE(&sub20, clone.get());
    TAG2_SUB20_EQ(*std::static_pointer_cast<OpenPGP::Subpacket::Tag2::Sub20>(clone));
}
