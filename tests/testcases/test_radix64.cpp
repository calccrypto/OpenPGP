#include <gtest/gtest.h>

#include "radix64.h"

TEST(Radix64Test, test_rfc4648_base64_test_vectors){

    // ascii2radix64
    EXPECT_EQ(ascii2radix64(""), "");
    EXPECT_EQ(ascii2radix64("f"), "Zg==");
    EXPECT_EQ(ascii2radix64("fo"), "Zm8=");
    EXPECT_EQ(ascii2radix64("foo"), "Zm9v");
    EXPECT_EQ(ascii2radix64("foob"), "Zm9vYg==");
    EXPECT_EQ(ascii2radix64("fooba"), "Zm9vYmE=");
    EXPECT_EQ(ascii2radix64("foobar"), "Zm9vYmFy");

    // radix642ascii
    EXPECT_EQ(radix642ascii(""), "");
    EXPECT_EQ(radix642ascii("Zg=="), "f");
    EXPECT_EQ(radix642ascii("Zm8="), "fo");
    EXPECT_EQ(radix642ascii("Zm9v"), "foo");
    EXPECT_EQ(radix642ascii("Zm9vYg=="), "foob");
    EXPECT_EQ(radix642ascii("Zm9vYmE="), "fooba");
    EXPECT_EQ(radix642ascii("Zm9vYmFy"), "foobar");

}
