#include <vector>

#include <gtest/gtest.h>

#include "common/includes.h"
#include "Packets/Tag8.h"
#include "Packets/Tag11.h"
#include "testvectors/msg.h"

static std::string TAG11_FILL() {
    OpenPGP::Packet::Tag11 tag11;
    tag11.set_data_format(OpenPGP::Packet::Literal::TEXT);
    tag11.set_filename("test");
    tag11.set_time(0);
    tag11.set_literal(MESSAGE);
    return tag11.write();
}

static const std::string message = TAG11_FILL();

static void TAG8_FILL(OpenPGP::Packet::Tag8 & tag8, const uint8_t comp) {
    tag8.set_comp(comp);
    tag8.set_data(message);
}

#define TAG8_EQ(tag8, comp)                                     \
    EXPECT_EQ((tag8).get_comp(), comp);                         \
    EXPECT_EQ((tag8).get_data(), message);                      \
    EXPECT_EQ((tag8).valid(true), OpenPGP::Status::SUCCESS);

TEST(Tag8, Constructor) {
    using namespace OpenPGP::Compression;

    // Default constructor
    OpenPGP::Packet::Tag8 tag8;
    EXPECT_EQ(tag8.raw(), std::string("\x00", 1));

    for(uint8_t comp : {ID::UNCOMPRESSED, ID::ZIP, ID::ZLIB, ID::BZIP2}) {
        EXPECT_NO_THROW(TAG8_FILL(tag8, comp));

        // String Constructor
        {
            OpenPGP::Packet::Tag8 str(tag8.raw());
            TAG8_EQ(str, comp);
        }

        // Copy Constructor
        {
            OpenPGP::Packet::Tag8 copy(tag8);
            TAG8_EQ(copy, comp);
        }

        // Move Constructor
        {
            OpenPGP::Packet::Tag8 move(std::move(tag8));
            TAG8_EQ(move, comp);
        }
    }
}

TEST(Tag8, Assignment) {
    using namespace OpenPGP::Compression;

    OpenPGP::Packet::Tag8 tag8;
    for(uint8_t comp : {ID::UNCOMPRESSED, ID::ZIP, ID::ZLIB, ID::BZIP2}) {
        EXPECT_NO_THROW(TAG8_FILL(tag8, comp));

        // Assignment
        {
            OpenPGP::Packet::Tag8 copy;
            copy = tag8;
            TAG8_EQ(copy, comp);
        }

        // Move Assignment
        {
            OpenPGP::Packet::Tag8 move;
            move = std::move(tag8);
            TAG8_EQ(move, comp);
        }
    }
}

TEST(Tag8, read_write) {
    using namespace OpenPGP::Compression;

    for(uint8_t comp : {ID::UNCOMPRESSED, ID::ZIP, ID::ZLIB, ID::BZIP2}) {
        const std::string raw = std::string(1, comp) + compress(comp, message);
        OpenPGP::Packet::Tag8 tag8(raw);
        TAG8_EQ(tag8, comp);
        EXPECT_EQ(tag8.raw(), raw);
    }
}

TEST(Tag8, show) {
    using namespace OpenPGP::Compression;

    for(uint8_t comp : {ID::UNCOMPRESSED, ID::ZIP, ID::ZLIB, ID::BZIP2}) {
        OpenPGP::Packet::Tag8 tag8;
        tag8.set_comp(comp);
        EXPECT_NO_THROW(tag8.show()); // show empty
        EXPECT_NO_THROW(TAG8_FILL(tag8, comp));
        EXPECT_NO_THROW(tag8.show()); // show filled
    }
}

TEST(Tag8, set_get) {
    using namespace OpenPGP::Compression;

    OpenPGP::Packet::Tag8 tag8;
    for(uint8_t comp : {ID::UNCOMPRESSED, ID::ZIP, ID::ZLIB, ID::BZIP2}) {
        EXPECT_NO_THROW(TAG8_FILL(tag8, comp));
        TAG8_EQ(tag8, comp);
    }
}

TEST(Tag8, clone) {
    using namespace OpenPGP::Compression;

    OpenPGP::Packet::Tag8 tag8;
    for(uint8_t comp : {ID::UNCOMPRESSED, ID::ZIP, ID::ZLIB, ID::BZIP2}) {
        EXPECT_NO_THROW(TAG8_FILL(tag8, comp));

        OpenPGP::Packet::Tag::Ptr clone = tag8.clone();
        EXPECT_NE(&tag8, clone.get());
        TAG8_EQ(*std::static_pointer_cast<OpenPGP::Packet::Tag8>(clone), comp);
    }
}
