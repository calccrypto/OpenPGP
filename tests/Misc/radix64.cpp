#include <gtest/gtest.h>

#include "Misc/radix64.h"

TEST(Radix64, rfc4648_base64_test_vectors){

    // OpenPGP::ascii2radix64
    EXPECT_EQ(OpenPGP::ascii2radix64(""), "");
    EXPECT_EQ(OpenPGP::ascii2radix64("f"), "Zg==");
    EXPECT_EQ(OpenPGP::ascii2radix64("fo"), "Zm8=");
    EXPECT_EQ(OpenPGP::ascii2radix64("foo"), "Zm9v");
    EXPECT_EQ(OpenPGP::ascii2radix64("foob"), "Zm9vYg==");
    EXPECT_EQ(OpenPGP::ascii2radix64("fooba"), "Zm9vYmE=");
    EXPECT_EQ(OpenPGP::ascii2radix64("foobar"), "Zm9vYmFy");

    // OpenPGP::radix642ascii
    EXPECT_EQ(OpenPGP::radix642ascii(""), "");
    EXPECT_EQ(OpenPGP::radix642ascii("Zg=="), "f");
    EXPECT_EQ(OpenPGP::radix642ascii("Zm8="), "fo");
    EXPECT_EQ(OpenPGP::radix642ascii("Zm9v"), "foo");
    EXPECT_EQ(OpenPGP::radix642ascii("Zm9vYg=="), "foob");
    EXPECT_EQ(OpenPGP::radix642ascii("Zm9vYmE="), "fooba");
    EXPECT_EQ(OpenPGP::radix642ascii("Zm9vYmFy"), "foobar");

}
