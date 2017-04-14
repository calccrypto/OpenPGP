#include <gtest/gtest.h>

#include "Compress/Compress.h"

#include "../testvectors/msg.h"

TEST(Compress, deflate) {
    auto compressed = PGP_compress(Compression::ZIP, MESSAGE);
    auto decompressed = PGP_decompress(Compression::ZIP, compressed);
    EXPECT_EQ(decompressed, MESSAGE);
}

TEST(Compress, zlib) {
    auto compressed = PGP_compress(Compression::ZLIB, MESSAGE);
    auto decompressed = PGP_decompress(Compression::ZLIB, compressed);
    EXPECT_EQ(decompressed, MESSAGE);
}

TEST(Compress, bzip2) {
    auto compressed = PGP_compress(Compression::BZIP2, MESSAGE);
    auto decompressed = PGP_decompress(Compression::BZIP2, compressed);
    EXPECT_EQ(decompressed, MESSAGE);
}

