#include <gtest/gtest.h>

#include "Packets/Tag12.h"

static const std::string trust = "trust";

static void TAG12_FILL(OpenPGP::Packet::Tag12 & tag12) {
    tag12.set_trust(trust);
}

#define TAG12_EQ(tag12)                                                 \
    EXPECT_EQ((tag12).get_trust(), trust);                              \
    EXPECT_EQ((tag12).valid(true), OpenPGP::Status::SHOULD_NOT_BE_EMITTED);

TEST(Tag12, Constructor) {
    // Default constructor
    OpenPGP::Packet::Tag12 tag12;

    EXPECT_EQ(tag12.raw(), "");
    EXPECT_NO_THROW(TAG12_FILL(tag12));

    // String Constructor
    {
        OpenPGP::Packet::Tag12 str(tag12.raw());
        TAG12_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Packet::Tag12 copy(tag12);
        TAG12_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Packet::Tag12 move(std::move(tag12));
        TAG12_EQ(move);
    }
}

TEST(Tag12, Assignment) {
    OpenPGP::Packet::Tag12 tag12;
    EXPECT_NO_THROW(TAG12_FILL(tag12));

    // Assignment
    {
        OpenPGP::Packet::Tag12 copy;
        copy = tag12;
        TAG12_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Packet::Tag12 move;
        move = std::move(tag12);
        TAG12_EQ(move);
    }
}

TEST(Tag12, read_write) {
    OpenPGP::Packet::Tag12 tag12(trust);
    TAG12_EQ(tag12);
    EXPECT_EQ(tag12.raw(), trust);
}

TEST(Tag12, show) {
    OpenPGP::Packet::Tag12 tag12;
    EXPECT_NO_THROW(TAG12_FILL(tag12));
    EXPECT_NO_THROW(tag12.show());
}

TEST(Tag12, set_get) {
    OpenPGP::Packet::Tag12 tag12;
    TAG12_FILL(tag12);
    TAG12_EQ(tag12);
}

TEST(Tag12, clone) {
    OpenPGP::Packet::Tag12 tag12;
    EXPECT_NO_THROW(TAG12_FILL(tag12));

    OpenPGP::Packet::Tag::Ptr clone = tag12.clone();
    EXPECT_NE(&tag12, clone.get());
    TAG12_EQ(*std::static_pointer_cast<OpenPGP::Packet::Tag12>(clone));
}
