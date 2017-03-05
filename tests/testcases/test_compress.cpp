#include <gtest/gtest.h>

#include "Compress/Compress.h"

TEST(CompressTest, test_deflate) {
    std::string message = "The magic words are squeamish ossifrage\n";
    auto compressed = PGP_compress(Compression::Algorithm::ZIP, message);
    auto decompressed = PGP_decompress(Compression::Algorithm::ZIP, compressed);
    EXPECT_EQ(decompressed, message);
}

TEST(CompressTest, test_zlib) {
    std::string message = "The magic words are squeamish ossifrage\n";
    auto compressed = PGP_compress(Compression::Algorithm::ZLIB, message);
    auto decompressed = PGP_decompress(Compression::Algorithm::ZLIB, compressed);
    EXPECT_EQ(decompressed, message);
}

TEST(CompressTest, test_bzip2) {
    std::string message = "The magic words are squeamish ossifrage\n";
    auto compressed = PGP_compress(Compression::Algorithm::BZIP2, message);
    auto decompressed = PGP_decompress(Compression::Algorithm::BZIP2, compressed);
    EXPECT_EQ(decompressed, message);
}

