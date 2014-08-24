#include <gtest/gtest.h>

#include "Compress/Compress.h"

TEST(CompressTest, test_deflate) {
    std::string message = "The magic words are squeamish ossifrage\n";
    auto compressed = PGP_compress(1, message);
    auto decompressed = PGP_decompress(1, compressed);
    EXPECT_EQ(decompressed, message);
}

TEST(CompressTest, test_zlib) {
    std::string message = "The magic words are squeamish ossifrage\n";
    auto compressed = PGP_compress(2, message);
    auto decompressed = PGP_decompress(2, compressed);
    EXPECT_EQ(decompressed, message);
}

TEST(CompressTest, test_bzip2) {
    std::string message = "The magic words are squeamish ossifrage\n";
    auto compressed = PGP_compress(3, message);
    auto decompressed = PGP_decompress(3, compressed);
    EXPECT_EQ(decompressed, message);
}

