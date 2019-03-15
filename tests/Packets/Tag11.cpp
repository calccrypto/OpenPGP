#include <vector>

#include <gtest/gtest.h>

#include "common/includes.h"
#include "Packets/Tag11.h"

static const std::string filename = "";
static const uint32_t timestamp = 0;
static const std::string literal = "";

static void TAG11_FILL(OpenPGP::Packet::Tag11 & tag11, const uint8_t format) {
    tag11.set_data_format(format);
    tag11.set_filename(filename);
    tag11.set_time(timestamp);
    tag11.set_literal(literal);
}

#define TAG11_EQ(tag11, format)                           \
    EXPECT_EQ((tag11).get_data_format(), (format));       \
    EXPECT_EQ((tag11).get_filename(), filename);          \
    EXPECT_EQ((tag11).get_time(), timestamp);             \
    EXPECT_EQ((tag11).get_literal(), literal);

TEST(Tag11, Constructor) {
    // Default constructor
    OpenPGP::Packet::Tag11 tag11;

    EXPECT_EQ(tag11.raw(), std::string("\x00\x00\x00\x00\x00\x00", 6));
    EXPECT_NO_THROW(TAG11_FILL(tag11, OpenPGP::Packet::Literal::BINARY));

    // String Constructor
    {
        OpenPGP::Packet::Tag11 str(tag11.raw());
        TAG11_EQ(str, OpenPGP::Packet::Literal::BINARY);
    }

    // Copy Constructor
    {
        OpenPGP::Packet::Tag11 copy(tag11);
        TAG11_EQ(copy, OpenPGP::Packet::Literal::BINARY);
    }

    // Move Constructor
    {
        OpenPGP::Packet::Tag11 move(std::move(tag11));
        TAG11_EQ(move, OpenPGP::Packet::Literal::BINARY);
    }
}

TEST(Tag11, Assignment) {
    OpenPGP::Packet::Tag11 tag11;
    EXPECT_NO_THROW(TAG11_FILL(tag11, OpenPGP::Packet::Literal::BINARY));

    // Assignment
    {
        OpenPGP::Packet::Tag11 copy;
        copy = tag11;
        TAG11_EQ(copy, OpenPGP::Packet::Literal::BINARY);
    }

    // Move Assignment
    {
        OpenPGP::Packet::Tag11 move;
        move = std::move(tag11);
        TAG11_EQ(move, OpenPGP::Packet::Literal::BINARY);
    }
}

TEST(Tag11, read_write) {
    for(auto data_format : OpenPGP::Packet::Literal::NAME) {
        const std::string raw = std::string(1, data_format.first) +
                                std::string(1, filename.size()) + filename +
                                unhexlify(makehex(timestamp, 8)) +
                                literal;

        OpenPGP::Packet::Tag11 tag11(raw);
        TAG11_EQ(tag11, data_format.first);
        EXPECT_EQ(tag11.raw(), raw);
    }
}

TEST(Tag11, set_get) {
    OpenPGP::Packet::Tag11 tag11;
    for(auto data_format : OpenPGP::Packet::Literal::NAME) {
        EXPECT_NO_THROW(TAG11_FILL(tag11, data_format.first));
        TAG11_EQ(tag11, data_format.first);
    }
}

TEST(Tag11, clone) {
    OpenPGP::Packet::Tag11 tag11;
    for(auto data_format : OpenPGP::Packet::Literal::NAME) {
        EXPECT_NO_THROW(TAG11_FILL(tag11, data_format.first));

        OpenPGP::Packet::Tag::Ptr clone = tag11.clone();
        EXPECT_NE(&tag11, clone.get());
        TAG11_EQ(*std::static_pointer_cast<OpenPGP::Packet::Tag11>(clone), data_format.first);
    }
}
