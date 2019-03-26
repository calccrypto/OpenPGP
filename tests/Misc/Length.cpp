#include <gtest/gtest.h>

#include "Misc/Length.h"

static const uint8_t tag = OpenPGP::Packet::RESERVED;

TEST(write_old_length, one_octet) {
    std::string data(255, '\x00');

    // pick a few sizes to check
    for(uint8_t const i : {0, 1, 2, 4, 8, 16, 32, 64, 128, 255}) {
        data.resize(i);

        {
            // write a 1 octet length
            const std::string out = OpenPGP::write_old_length(tag, data, OpenPGP::Packet::PartialBodyLength::NOT_PARTIAL);

            // reduce copying when doing comparison
            EXPECT_EQ((uint8_t) out[0], 0x80 | (tag << 2) | 0x00);
            EXPECT_EQ((uint8_t) out[1], data.size());
            EXPECT_EQ(out.compare(2, i, data), 0);
        }

        {
            // force write a 1 octet length
            const std::string out = OpenPGP::write_old_length(tag, data, OpenPGP::Packet::PartialBodyLength::NOT_PARTIAL, 1);

            // reduce copying when doing comparison
            EXPECT_EQ((uint8_t) out[0], 0x80 | (tag << 2) | 0x00);
            EXPECT_EQ((uint8_t) out[1], data.size());
            EXPECT_EQ(out.compare(2, i, data), 0);
        }
    }
}

TEST(write_old_length, two_octet) {
    {
        const std::string data(256, '\x00');

        // write a 2 octet length
        const std::string out = OpenPGP::write_old_length(tag, data, OpenPGP::Packet::PartialBodyLength::NOT_PARTIAL);

        // reduce copying when doing comparison
        EXPECT_EQ((uint8_t) out[0], 0x80 | (tag << 2) | 0x01);
        EXPECT_EQ((uint8_t) out[1], (data.size() >> 8) & 0xff);
        EXPECT_EQ((uint8_t) out[2], (data.size() >> 0) & 0xff);
        EXPECT_EQ(out.compare(3, data.size(), data), 0);
    }

    {
        const std::string data(255, '\x00');

        // force write a 2 octet length
        const std::string out = OpenPGP::write_old_length(tag, data, OpenPGP::Packet::PartialBodyLength::NOT_PARTIAL, 2);

        // reduce copying when doing comparison
        EXPECT_EQ((uint8_t) out[0], 0x80 | (tag << 2) | 0x01);
        EXPECT_EQ((uint8_t) out[1], 0);
        EXPECT_EQ((uint8_t) out[2], data.size());
        EXPECT_EQ(out.compare(3, data.size(), data), 0);
    }
}

TEST(write_old_length, four_octet) {
    {
        const std::string data(65536, '\x00');

        // write a 5-octet length
        const std::string out = OpenPGP::write_old_length(tag, data, OpenPGP::Packet::PartialBodyLength::NOT_PARTIAL);

        // reduce copying when doing comparison
        EXPECT_EQ((uint8_t) out[0], 0x80 | (tag << 2) | 0x02);
        EXPECT_EQ((uint8_t) out[1], (data.size() >> 24) & 0xff);
        EXPECT_EQ((uint8_t) out[2], (data.size() >> 16) & 0xff);
        EXPECT_EQ((uint8_t) out[3], (data.size() >>  8) & 0xff);
        EXPECT_EQ((uint8_t) out[4], (data.size() >>  0) & 0xff);
        EXPECT_EQ(out.compare(5, data.size(), data), 0);
    }

    {
        const std::string data(255, '\x00');

        // force write a 5-octet length
        const std::string out = OpenPGP::write_old_length(tag, data, OpenPGP::Packet::PartialBodyLength::NOT_PARTIAL, 5);

        // reduce copying when doing comparison
        EXPECT_EQ((uint8_t) out[0], 0x80 | (tag << 2) | 0x02);
        EXPECT_EQ((uint8_t) out[1], 0);
        EXPECT_EQ((uint8_t) out[2], 0);
        EXPECT_EQ((uint8_t) out[3], 0);
        EXPECT_EQ((uint8_t) out[4], data.size());
        EXPECT_EQ(out.compare(5, data.size(), data), 0);
    }
}

TEST(write_old_length, partial) {
    std::string data(255, '\x00');

    // write a partial length
    const std::string out = OpenPGP::write_old_length(tag, data, OpenPGP::Packet::PartialBodyLength::PARTIAL);

    // reduce copying when doing comparison
    EXPECT_EQ((uint8_t) out[0], 0x80 | (tag << 2) | 0x03);
    EXPECT_EQ(out.compare(1, data.size(), data), 0);
}

TEST(write_new_length, one_octet) {
    std::string data(192, '\x00');

    // pick a few sizes to check
    for(uint8_t const i : {0, 1, 2, 4, 8, 16, 32, 64, 128, 191}) {
        data.resize(i);

        {
            // write a 1 octet length
            const std::string out = OpenPGP::write_new_length(tag, data, OpenPGP::Packet::PartialBodyLength::NOT_PARTIAL);

            // reduce copying when doing comparison
            EXPECT_EQ((uint8_t) out[0], 0xc0 | tag);
            EXPECT_EQ((uint8_t) out[1], data.size());
            EXPECT_EQ(out.compare(2, i, data), 0);
        }

        {
            // force write a 1 octet length
            const std::string out = OpenPGP::write_new_length(tag, data, OpenPGP::Packet::PartialBodyLength::NOT_PARTIAL, 1);

            // reduce copying when doing comparison
            EXPECT_EQ((uint8_t) out[0], 0xc0 | tag);
            EXPECT_EQ((uint8_t) out[1], data.size());
            EXPECT_EQ(out.compare(2, i, data), 0);
        }
    }
}

TEST(write_new_length, two_octet) {
    {
        const std::string data(192, '\x00');

        // write a 2-octet length
        const std::string out = OpenPGP::write_new_length(tag, data, OpenPGP::Packet::PartialBodyLength::NOT_PARTIAL);

        // reduce copying when doing comparison
        EXPECT_EQ((uint8_t) out[0], 0xc0 | tag);
        EXPECT_EQ((((out[1] & 0xffU) - 192) << 8) + (out[2] & 0xffU) + 192U, data.size());
        EXPECT_EQ(out.compare(3, data.size(), data), 0);
    }

    {
        const std::string data(128, '\x00');

        // force write a 2-octet length
        const std::string out = OpenPGP::write_new_length(tag, data, OpenPGP::Packet::PartialBodyLength::NOT_PARTIAL, 2);

        // reduce copying when doing comparison
        EXPECT_EQ((uint8_t) out[0], 0xc0 | tag);
        EXPECT_EQ((((out[1] & 0xffU) - 192) << 8) + (out[2] & 0xffU) + 192U, data.size());
        EXPECT_EQ(out.compare(3, data.size(), data), 0);
    }
}

TEST(write_new_length, four_octet) {
    {
        const std::string data(8384, '\x00');

        // write a 5-octet length
        const std::string out = OpenPGP::write_new_length(tag, data, OpenPGP::Packet::PartialBodyLength::NOT_PARTIAL);

        // reduce copying when doing comparison
        EXPECT_EQ((uint8_t) out[0], 0xc0 | tag);
        EXPECT_EQ((uint8_t) out[1], 0xff);
        EXPECT_EQ((uint8_t) out[2], (data.size() >> 24) & 0xff);
        EXPECT_EQ((uint8_t) out[3], (data.size() >> 16) & 0xff);
        EXPECT_EQ((uint8_t) out[4], (data.size() >>  8) & 0xff);
        EXPECT_EQ((uint8_t) out[5], (data.size() >>  0) & 0xff);
        EXPECT_EQ(out.compare(6, data.size(), data), 0);
    }

    {
        const std::string data(128, '\x00');

        // force write a 5-octet length
        const std::string out = OpenPGP::write_new_length(tag, data, OpenPGP::Packet::PartialBodyLength::NOT_PARTIAL, 5);

        // reduce copying when doing comparison
        EXPECT_EQ((uint8_t) out[0], 0xc0 | tag);
        EXPECT_EQ((uint8_t) out[1], 0xff);
        EXPECT_EQ((uint8_t) out[2], 0);
        EXPECT_EQ((uint8_t) out[3], 0);
        EXPECT_EQ((uint8_t) out[4], 0);
        EXPECT_EQ((uint8_t) out[5], data.size());
        EXPECT_EQ(out.compare(6, data.size(), data), 0);
    }
}

TEST(write_new_length, partial) {
    std::string data(513, '\x00');

    // write a partial length
    const std::string out = OpenPGP::write_new_length(tag, data, OpenPGP::Packet::PartialBodyLength::PARTIAL);

    // move last octet to the next length header
    const char last = data.back();
    data.pop_back();

    // add last length header
    data += std::string(1, (uint8_t) (0xc0 | tag)) + std::string(1, '\x01') + std::string(1, last);

    // reduce copying when doing comparison
    EXPECT_EQ((uint8_t) out[0], 0xc0 | tag);
    EXPECT_EQ((uint8_t) out[1], 0xe0 + 9);
    EXPECT_EQ(out.compare(2, data.size(), data), 0);
}
