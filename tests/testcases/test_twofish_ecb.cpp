#include <gtest/gtest.h>

#include "Encryptions/Twofish.h"

#include "testvectors/twofish/twofishecb_vk.h"
#include "testvectors/twofish/twofishecb_vt.h"

// Test vectors from <https://www.schneier.com/code/twofish-kat.zip>

TEST(TwofishTest, test_twofish128_ecb_ival) {

    std::string key(16, 0);
    std::string plain(16, 0);
    std::string cipher = unhexlify("9F589F5CF6122C32B6BFEC2F2AE8C35A");

    auto twofish = Twofish(key);
    EXPECT_EQ(twofish.encrypt(plain), cipher);
    EXPECT_EQ(twofish.decrypt(cipher), plain);
}

TEST(TwofishTest, test_twofish192_ecb_ival) {

    std::string key = unhexlify("0123456789ABCDEFFEDCBA98765432100011223344556677");
    std::string plain(16, 0);
    std::string cipher = unhexlify("CFD1D2E5A9BE9CDF501F13B892BD2248");

    auto twofish = Twofish(key);
    EXPECT_EQ(twofish.encrypt(plain), cipher);
    EXPECT_EQ(twofish.decrypt(cipher), plain);

}

TEST(TwofishTest, test_twofish256_ecb_ival) {

    std::string key = unhexlify("0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF");
    std::string plain(16, 0);
    std::string cipher = unhexlify("37527BE0052334B89F0CFCCAE87CFA20");

    auto twofish = Twofish(key);
    EXPECT_EQ(twofish.encrypt(plain), cipher);
    EXPECT_EQ(twofish.decrypt(cipher), plain);

}

TEST(TwofishTest, test_twofish128_ecb_tbl) {

    std::string key(16, 0);
    std::string plain(16, 0);

    for ( unsigned int i = 0; i < 49; ++i ) {
        auto twofish = Twofish(key);
        key = plain;
        plain = twofish.encrypt(plain);
    }

    EXPECT_EQ(plain, unhexlify("5D9D4EEFFA9151575524F115815A12E0"));

}

TEST(TwofishTest, test_twofish192_ecb_tbl) {
    std::string key(24, 0);
    std::string plain(16, 0);

    for ( unsigned int i = 0; i < 49; ++i ) {
        auto twofish = Twofish(key);
        key = (plain + key).substr(0, 24);
        plain = twofish.encrypt(plain);
    }

    EXPECT_EQ(plain, unhexlify("E75449212BEEF9F4A390BD860A640941"));

}

TEST(TwofishTest, test_twofish1256_ecb_tbl) {
    std::string key(32, 0);
    std::string plain(16, 0);

    for ( unsigned int i = 0; i < 49; ++i ) {
        auto twofish = Twofish(key);
        key = (plain + key).substr(0, 32);
        plain = twofish.encrypt(plain);
    }

    EXPECT_EQ(plain, unhexlify("37FE26FF1CF66175F5DDF4C33B97A205"));

}

TEST(TwofishTest, test_twofish128_ecb_vk) {

    ASSERT_EQ(TWOFISH128_ECB_VK_KEY.size(), TWOFISH128_ECB_VK_CIPHER.size());

    std::string UNHEX_TWOFISH_ECB_VK_PLAIN = unhexlify(TWOFISH_ECB_VK_PLAIN);

    for ( unsigned int i = 0; i < TWOFISH128_ECB_VK_KEY.size(); ++i ) {
        auto twofish128 = Twofish(unhexlify(TWOFISH128_ECB_VK_KEY[i]));
        EXPECT_EQ(twofish128.encrypt(UNHEX_TWOFISH_ECB_VK_PLAIN), unhexlify(TWOFISH128_ECB_VK_CIPHER[i]));
        EXPECT_EQ(twofish128.decrypt(unhexlify(TWOFISH128_ECB_VK_CIPHER[i])), UNHEX_TWOFISH_ECB_VK_PLAIN);
    }
}

TEST(TwofishTest, test_twofish192_ecb_vk) {

    ASSERT_EQ(TWOFISH192_ECB_VK_KEY.size(), TWOFISH192_ECB_VK_CIPHER.size());

    std::string UNHEX_TWOFISH_ECB_VK_PLAIN = unhexlify(TWOFISH_ECB_VK_PLAIN);

    for ( unsigned int i = 0; i < TWOFISH192_ECB_VK_KEY.size(); ++i ) {
        auto twofish192 = Twofish(unhexlify(TWOFISH192_ECB_VK_KEY[i]));
        EXPECT_EQ(twofish192.encrypt(UNHEX_TWOFISH_ECB_VK_PLAIN), unhexlify(TWOFISH192_ECB_VK_CIPHER[i]));
        EXPECT_EQ(twofish192.decrypt(unhexlify(TWOFISH192_ECB_VK_CIPHER[i])), UNHEX_TWOFISH_ECB_VK_PLAIN);
    }
}

TEST(TwofishTest, test_twofish256_ecb_vk) {

    ASSERT_EQ(TWOFISH256_ECB_VK_KEY.size(), TWOFISH256_ECB_VK_CIPHER.size());

    std::string UNHEX_TWOFISH_ECB_VK_PLAIN = unhexlify(TWOFISH_ECB_VK_PLAIN);

    for ( unsigned int i = 0; i < TWOFISH256_ECB_VK_KEY.size(); ++i ) {
        auto twofish256 = Twofish(unhexlify(TWOFISH256_ECB_VK_KEY[i]));
        EXPECT_EQ(twofish256.encrypt(UNHEX_TWOFISH_ECB_VK_PLAIN), unhexlify(TWOFISH256_ECB_VK_CIPHER[i]));
        EXPECT_EQ(twofish256.decrypt(unhexlify(TWOFISH256_ECB_VK_CIPHER[i])), UNHEX_TWOFISH_ECB_VK_PLAIN);
    }
}

TEST(TwofishTest, test_twofish128_ecb_vt) {

    ASSERT_EQ(TWOFISH_ECB_VT_PLAIN.size(), TWOFISH128_ECB_VT_CIPHER.size());

    std::string UNHEX_TWOFISH128_ECB_VT_KEY = unhexlify(TWOFISH128_ECB_VT_KEY);

    for ( unsigned int i = 0; i < TWOFISH_ECB_VT_PLAIN.size(); ++i ) {
        auto twofish128 = Twofish(UNHEX_TWOFISH128_ECB_VT_KEY);
        EXPECT_EQ(twofish128.encrypt(unhexlify(TWOFISH_ECB_VT_PLAIN[i])), unhexlify(TWOFISH128_ECB_VT_CIPHER[i]));
        EXPECT_EQ(twofish128.decrypt(unhexlify(TWOFISH128_ECB_VT_CIPHER[i])), unhexlify(TWOFISH_ECB_VT_PLAIN[i]));
    }
}

TEST(TwofishTest, test_twofish192_ecb_vt) {

    ASSERT_EQ(TWOFISH_ECB_VT_PLAIN.size(), TWOFISH192_ECB_VT_CIPHER.size());

    std::string UNHEX_TWOFISH192_ECB_VT_KEY = unhexlify(TWOFISH192_ECB_VT_KEY);

    for ( unsigned int i = 0; i < TWOFISH_ECB_VT_PLAIN.size(); ++i ) {
        auto twofish192 = Twofish(UNHEX_TWOFISH192_ECB_VT_KEY);
        EXPECT_EQ(twofish192.encrypt(unhexlify(TWOFISH_ECB_VT_PLAIN[i])), unhexlify(TWOFISH192_ECB_VT_CIPHER[i]));
        EXPECT_EQ(twofish192.decrypt(unhexlify(TWOFISH192_ECB_VT_CIPHER[i])), unhexlify(TWOFISH_ECB_VT_PLAIN[i]));
    }
}

TEST(TwofishTest, test_twofish256_ecb_vt) {

    ASSERT_EQ(TWOFISH_ECB_VT_PLAIN.size(), TWOFISH256_ECB_VT_CIPHER.size());

    std::string UNHEX_TWOFISH256_ECB_VT_KEY = unhexlify(TWOFISH256_ECB_VT_KEY);

    for ( unsigned int i = 0; i < TWOFISH_ECB_VT_PLAIN.size(); ++i ) {
        auto twofish256 = Twofish(UNHEX_TWOFISH256_ECB_VT_KEY);
        EXPECT_EQ(twofish256.encrypt(unhexlify(TWOFISH_ECB_VT_PLAIN[i])), unhexlify(TWOFISH256_ECB_VT_CIPHER[i]));
        EXPECT_EQ(twofish256.decrypt(unhexlify(TWOFISH256_ECB_VT_CIPHER[i])), unhexlify(TWOFISH_ECB_VT_PLAIN[i]));
    }
}

