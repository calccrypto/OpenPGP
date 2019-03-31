#include <gtest/gtest.h>

#include "Packets/Tag13.h"

static const std::string name     = "name";
static const std::string comment  = "comment";
static const std::string email    = "name@email.com";
static const std::string contents = name + " (" + comment + ")" + " <" + email + ">";

static void TAG13_FILL(OpenPGP::Packet::Tag13 & tag13) {
    tag13.set_contents(contents);
}

#define TAG13_EQ(tag13)                                         \
    EXPECT_EQ((tag13).get_contents(), contents);                \
    EXPECT_EQ((tag13).valid(true), OpenPGP::Status::SUCCESS);

TEST(Tag13, Constructor) {
    // Default constructor
    OpenPGP::Packet::Tag13 tag13;

    EXPECT_EQ(tag13.raw(), "");
    EXPECT_NO_THROW(TAG13_FILL(tag13));

    // String Constructor
    {
        OpenPGP::Packet::Tag13 str(tag13.raw());
        TAG13_EQ(str);
    }

    // Copy Constructor
    {
        OpenPGP::Packet::Tag13 copy(tag13);
        TAG13_EQ(copy);
    }

    // Move Constructor
    {
        OpenPGP::Packet::Tag13 move(std::move(tag13));
        TAG13_EQ(move);
    }
}

TEST(Tag13, Assignment) {
    OpenPGP::Packet::Tag13 tag13;
    EXPECT_NO_THROW(TAG13_FILL(tag13));

    // Assignment
    {
        OpenPGP::Packet::Tag13 copy;
        copy = tag13;
        TAG13_EQ(copy);
    }

    // Move Assignment
    {
        OpenPGP::Packet::Tag13 move;
        move = std::move(tag13);
        TAG13_EQ(move);
    }
}

TEST(Tag13, read_write) {
    OpenPGP::Packet::Tag13 tag13(contents);
    TAG13_EQ(tag13);
    EXPECT_EQ(tag13.raw(), contents);
}

TEST(Tag13, set_get) {
    OpenPGP::Packet::Tag13 tag13;
    TAG13_FILL(tag13);
    TAG13_EQ(tag13);
}

TEST(Tag13, set_get_info) {
    OpenPGP::Packet::Tag13 tag13;

    // set the user information in pieces
    EXPECT_NO_THROW(tag13.set_info("", "", ""));
    EXPECT_EQ(tag13.get_contents(), "");

    EXPECT_NO_THROW(tag13.set_info(name, "", ""));
    EXPECT_EQ(tag13.get_contents(), name);
    EXPECT_NO_THROW(tag13.set_info("", comment, ""));
    EXPECT_EQ(tag13.get_contents(), "(" + comment + ")");
    EXPECT_NO_THROW(tag13.set_info("", "", email));
    EXPECT_EQ(tag13.get_contents(), "<" + email + ">");

    EXPECT_NO_THROW(tag13.set_info(name, comment, ""));
    EXPECT_EQ(tag13.get_contents(), name + " (" + comment + ")");

    EXPECT_NO_THROW(tag13.set_info(name, "", email));
    EXPECT_EQ(tag13.get_contents(), name + " <" + email + ">");

    EXPECT_NO_THROW(tag13.set_info("", comment, email));
    EXPECT_EQ(tag13.get_contents(), "(" + comment + ")" + " <" + email + ">");

    EXPECT_NO_THROW(tag13.set_info(name, comment, email));
    EXPECT_EQ(tag13.get_contents(), contents);
}

TEST(Tag13, clone) {
    OpenPGP::Packet::Tag13 tag13;
    EXPECT_NO_THROW(TAG13_FILL(tag13));

    OpenPGP::Packet::Tag::Ptr clone = tag13.clone();
    EXPECT_NE(&tag13, clone.get());
    TAG13_EQ(*std::static_pointer_cast<OpenPGP::Packet::Tag13>(clone));
}
