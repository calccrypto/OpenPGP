#include <gtest/gtest.h>

#include "Encryptions/CAST128.h"

TEST(CAST128Test, test_cast128_ecb) {

    // Test vector from <http://tools.ietf.org/html/rfc2144#appendix-B>
    const std::string CAST128_ECB_KEY = unhexlify("0123456712345678234567893456789a");
    const std::string CAST128_ECB_PLAIN = unhexlify("0123456789abcdef");
    const std::string CAST128_ECB_CIPHER = unhexlify("238B4fe5847e44b2");

    auto cast128 = CAST128(CAST128_ECB_KEY);
    EXPECT_EQ(cast128.encrypt(CAST128_ECB_PLAIN), CAST128_ECB_CIPHER);
    EXPECT_EQ(cast128.decrypt(CAST128_ECB_CIPHER), CAST128_ECB_PLAIN);

}

/*
TEST(CAST128Test, test_cast128_maintenance_test) {

    // Test vector from <http://tools.ietf.org/html/rfc2144#appendix-B>
    std::string aL, aR, bL, bR;
    aL = bL = unhexlify("0123456712345678");
    aR = bR = unhexlify("234567893456789a");

    // 1,000,000 times
    for ( unsigned int i = 0; i < 1000000; ++i ) {
        auto enc1 = CAST128(bL+bR);
        aL = enc1.encrypt(aL);
        aR = enc1.encrypt(aR);
        auto enc2 = CAST128(aL+aR);
        bL = enc2.encrypt(bL);
        bR = enc2.encrypt(bR);
    }

    EXPECT_EQ(aL+aR, unhexlify("eea9d0a249fd3ba6b3436fb89d6dca92"));
    EXPECT_EQ(bL+bR, unhexlify("b2c95eb00c31ad7180ac05b8e83d696e"));

}
*/
