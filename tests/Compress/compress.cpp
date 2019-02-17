#include <gtest/gtest.h>

#include "Compress/Compress.h"

#include "../testvectors/msg.h"

TEST(Compress, deflate) {
    auto compressed = OpenPGP::Compression::compress(OpenPGP::Compression::ID::ZIP, MESSAGE);
    auto decompressed = OpenPGP::Compression::decompress(OpenPGP::Compression::ID::ZIP, compressed);
    EXPECT_EQ(decompressed, MESSAGE);
}

TEST(Compress, zlib) {
    auto compressed = OpenPGP::Compression::compress(OpenPGP::Compression::ID::ZLIB, MESSAGE);
    auto decompressed = OpenPGP::Compression::decompress(OpenPGP::Compression::ID::ZLIB, compressed);
    EXPECT_EQ(decompressed, MESSAGE);
}

TEST(Compress, bzip2) {
    auto compressed = OpenPGP::Compression::compress(OpenPGP::Compression::ID::BZIP2, MESSAGE);
    auto decompressed = OpenPGP::Compression::decompress(OpenPGP::Compression::ID::BZIP2, compressed);
    EXPECT_EQ(decompressed, MESSAGE);
}

