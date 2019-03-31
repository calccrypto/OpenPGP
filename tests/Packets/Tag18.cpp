#include <gtest/gtest.h>

#include "Packets/Tag18.h"

static const uint8_t version = 1;
static const std::string protected_data = "";

static void TAG18_FILL(OpenPGP::Packet::Tag18 & tag18) {
    tag18.set_version(version);
    tag18.set_protected_data(protected_data);
}

#define TAG18_EQ(tag18)                                         \
    EXPECT_EQ((tag18).get_version(), version);                  \
    EXPECT_EQ((tag18).get_protected_data(), protected_data);    \
    EXPECT_EQ((tag18).valid(true), OpenPGP::Status::SUCCESS);

TEST(Tag18, Constructor) {
    // Default constructor
    OpenPGP::Packet::Tag18 tag18;

    EXPECT_EQ(tag18.raw(), std::string("\x01", 1));
    EXPECT_NO_THROW(TAG18_FILL(tag18));

    // String Constructor
    {
        OpenPGP::Packet::Tag18 str(tag18.raw());
        TAG18_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Packet::Tag18 copy(tag18);
        TAG18_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Packet::Tag18 move(std::move(tag18));
        TAG18_EQ(move);
    }
}

TEST(Tag18, Assignment) {
    OpenPGP::Packet::Tag18 tag18;
    EXPECT_NO_THROW(TAG18_FILL(tag18));

    // Assignment
    {
        OpenPGP::Packet::Tag18 copy;
        copy = tag18;
        TAG18_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Packet::Tag18 move;
        move = std::move(tag18);
        TAG18_EQ(move);
    }
}

TEST(Tag18, read_write) {
    const std::string raw = std::string(1, version) + protected_data;

    OpenPGP::Packet::Tag18 tag18(raw);
    TAG18_EQ(tag18);
    EXPECT_EQ(tag18.raw(), raw);
}

TEST(Tag18, set_get) {
    OpenPGP::Packet::Tag18 tag18;
    EXPECT_NO_THROW(TAG18_FILL(tag18));
    TAG18_EQ(tag18);
}

TEST(Tag18, clone) {
    OpenPGP::Packet::Tag18 tag18;
    EXPECT_NO_THROW(TAG18_FILL(tag18));

    OpenPGP::Packet::Tag::Ptr clone = tag18.clone();
    EXPECT_NE(&tag18, clone.get());
    TAG18_EQ(*std::static_pointer_cast<OpenPGP::Packet::Tag18>(clone));
}
