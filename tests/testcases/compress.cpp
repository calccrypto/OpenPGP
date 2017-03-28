#include <gtest/gtest.h>

#include "Compress/Compress.h"

TEST(Compress, deflate) {
    std::string message = "The magic words are squeamish ossifrage\n";
    auto compressed = PGP_compress(Compression::ZIP, message);
    auto decompressed = PGP_decompress(Compression::ZIP, compressed);
    EXPECT_EQ(decompressed, message);
}

TEST(Compress, zlib) {
    std::string message = "The magic words are squeamish ossifrage\n";
    auto compressed = PGP_compress(Compression::ZLIB, message);
    auto decompressed = PGP_decompress(Compression::ZLIB, compressed);
    EXPECT_EQ(decompressed, message);
}

TEST(Compress, bzip2) {
    std::string message = "The magic words are squeamish ossifrage\n";
    auto compressed = PGP_compress(Compression::BZIP2, message);
    auto decompressed = PGP_decompress(Compression::BZIP2, compressed);
    EXPECT_EQ(decompressed, message);
}

