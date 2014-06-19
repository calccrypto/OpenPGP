#include <gtest/gtest.h>

#include "Encryptions/Twofish.h"

// Test vectors from <https://www.schneier.com/code/ecb_ival.txt>

TEST(TwofishTest, test_twofish128_ecb) {

    std::string key(16, 0);
    std::string plain(16, 0);
    std::string cipher = unhexlify("9F589F5CF6122C32B6BFEC2F2AE8C35A");

    auto twofish = Twofish(key);
    EXPECT_EQ(twofish.encrypt(plain), cipher);
    EXPECT_EQ(twofish.decrypt(cipher), plain);
}

TEST(TwofishTest, test_twofish192_ecb) {

    std::string key = unhexlify("0123456789ABCDEFFEDCBA98765432100011223344556677");
    std::string plain(16, 0);
    std::string cipher = unhexlify("CFD1D2E5A9BE9CDF501F13B892BD2248");

    auto twofish = Twofish(key);
    EXPECT_EQ(twofish.encrypt(plain), cipher);
    EXPECT_EQ(twofish.decrypt(cipher), plain);

}

TEST(TwofishTest, test_twofish256_ecb) {

    std::string key = unhexlify("0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF");
    std::string plain(16, 0);
    std::string cipher = unhexlify("37527BE0052334B89F0CFCCAE87CFA20");

    auto twofish = Twofish(key);
    EXPECT_EQ(twofish.encrypt(plain), cipher);
    EXPECT_EQ(twofish.decrypt(cipher), plain);

}

TEST(TwofishTest, test_twofish128_ecb_full) {

    std::string key(16, 0);
    std::string plain(16, 0);

    for ( int i = 0; i < 49; ++i ) {
        auto twofish = Twofish(key);
        key = plain;
        plain = twofish.encrypt(plain);
    }

    EXPECT_EQ(plain, unhexlify("5D9D4EEFFA9151575524F115815A12E0"));

}

TEST(TwofishTest, test_twofish192_ecb_full) {
    std::string key(24, 0);
    std::string plain(16, 0);

    for ( int i = 0; i < 49; ++i ) {
        auto twofish = Twofish(key);
        key = (plain + key).substr(0, 24);
        plain = twofish.encrypt(plain);
    }

    EXPECT_EQ(plain, unhexlify("E75449212BEEF9F4A390BD860A640941"));

}

TEST(TwofishTest, test_twofish1256_ecb_full) {
    std::string key(32, 0);
    std::string plain(16, 0);

    for ( int i = 0; i < 49; ++i ) {
        auto twofish = Twofish(key);
        key = (plain + key).substr(0, 32);
        plain = twofish.encrypt(plain);
    }

    EXPECT_EQ(plain, unhexlify("37FE26FF1CF66175F5DDF4C33B97A205"));

}

