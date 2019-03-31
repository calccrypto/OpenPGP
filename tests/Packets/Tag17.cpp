#include <gtest/gtest.h>

#include "Packets/Tag17.h"

static const std::string image = std::string("\x10\x00\x01\x01", 4) + std::string(12, '\x00');
static const std::string sub1 = std::string(1, image.size() + 1) + std::string(1, '\x01') + image;

static void TAG17_FILL(OpenPGP::Packet::Tag17 & tag17) {
    tag17.read(sub1);
}

#define TAG17_EQ(tag17)                                                             \
    const OpenPGP::Packet::Tag17::Attributes attributes = (tag17).get_attributes(); \
    ASSERT_EQ(attributes.size(), 1);                                                \
    EXPECT_EQ(attributes[0] -> raw(), image);                                       \
    EXPECT_EQ((tag17).valid(true), OpenPGP::Status::SUCCESS);

TEST(Tag17, Constructor) {
    // Default constructor
    OpenPGP::Packet::Tag17 tag17;

    EXPECT_EQ(tag17.raw(), "");
    EXPECT_NO_THROW(TAG17_FILL(tag17));

    // String Constructor
    {
        OpenPGP::Packet::Tag17 str(tag17.raw());
        TAG17_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Packet::Tag17 copy(tag17);
        TAG17_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Packet::Tag17 move(std::move(tag17));
        TAG17_EQ(move);
    }
}

TEST(Tag17, Assignment) {
    OpenPGP::Packet::Tag17 tag17;
    EXPECT_NO_THROW(TAG17_FILL(tag17));

    // Assignment
    {
        OpenPGP::Packet::Tag17 copy;
        copy = tag17;
        TAG17_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Packet::Tag17 move;
        move = std::move(tag17);
        TAG17_EQ(move);
    }
}

TEST(Tag17, read_write) {
    OpenPGP::Packet::Tag17 tag17(sub1);
    TAG17_EQ(tag17);
    EXPECT_EQ(tag17.raw(), sub1);
}

TEST(Tag17, set_get) {
    OpenPGP::Packet::Tag17 tag17;
    TAG17_FILL(tag17);
    TAG17_EQ(tag17);
}

TEST(Tag17, clone) {
    OpenPGP::Packet::Tag17 tag17;
    EXPECT_NO_THROW(TAG17_FILL(tag17));

    OpenPGP::Packet::Tag::Ptr clone = tag17.clone();
    EXPECT_NE(&tag17, clone.get());
    TAG17_EQ(*std::static_pointer_cast<OpenPGP::Packet::Tag17>(clone));
}
