#include <gtest/gtest.h>

#include "Packets/Tag17/Sub1.h"

static const uint8_t version = 1;
static const uint8_t encoding = OpenPGP::Subpacket::Tag17::Image_Attributes::JPEG;
static const std::string image = "";
static const std::string raw = std::string("\x10\x00", 2) + std::string(1, version) + std::string(1, encoding) + std::string(12, '\x00') + image;

static void TAG17_SUB1_FILL(OpenPGP::Subpacket::Tag17::Sub1 & sub1) {
    sub1.set_version(version);
    sub1.set_encoding(encoding);
    sub1.set_image(image);
}

#define TAG17_SUB1_EQ(sub1)                                     \
    EXPECT_EQ((sub1).get_version(), version);                   \
    EXPECT_EQ((sub1).get_encoding(), encoding);                 \
    EXPECT_EQ((sub1).get_image(), image);                       \
    EXPECT_EQ((sub1).valid(true), OpenPGP::Status::SUCCESS);

TEST(Tag17Sub1, Constructor) {
    // Default constructor
    OpenPGP::Subpacket::Tag17::Sub1 sub1;

    EXPECT_EQ(sub1.raw(), raw);
    EXPECT_NO_THROW(TAG17_SUB1_FILL(sub1));

    // String Constructor
    {
        OpenPGP::Subpacket::Tag17::Sub1 str(sub1.raw());
        TAG17_SUB1_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Subpacket::Tag17::Sub1 copy(sub1);
        TAG17_SUB1_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Subpacket::Tag17::Sub1 move(std::move(sub1));
        TAG17_SUB1_EQ(move);
    }
}

TEST(Tag17Sub1, Assignment) {
    OpenPGP::Subpacket::Tag17::Sub1 sub1;
    EXPECT_NO_THROW(TAG17_SUB1_FILL(sub1));

    // Assignment
    {
        OpenPGP::Subpacket::Tag17::Sub1 copy;
        copy = sub1;
        TAG17_SUB1_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Subpacket::Tag17::Sub1 move;
        move = std::move(sub1);
        TAG17_SUB1_EQ(move);
    }
}

TEST(Tag17Sub1, read_write) {
    OpenPGP::Subpacket::Tag17::Sub1 sub1(raw);
    TAG17_SUB1_EQ(sub1);
    EXPECT_EQ(sub1.raw(), raw);
}

TEST(Tag17Sub1, set_get) {
    OpenPGP::Subpacket::Tag17::Sub1 sub1;
    TAG17_SUB1_FILL(sub1);
    TAG17_SUB1_EQ(sub1);
}

TEST(Tag17Sub1, clone) {
    OpenPGP::Subpacket::Tag17::Sub1 sub1;
    EXPECT_NO_THROW(TAG17_SUB1_FILL(sub1));

    OpenPGP::Subpacket::Tag17::Sub::Ptr clone = sub1.clone();
    EXPECT_NE(&sub1, clone.get());
    TAG17_SUB1_EQ(*std::static_pointer_cast<OpenPGP::Subpacket::Tag17::Sub1>(clone));
}
