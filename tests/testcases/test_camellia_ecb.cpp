#include <gtest/gtest.h>

#include "Encryptions/Camellia.h"

#include "testvectors/camellia/camelliatestvectors.h"

TEST(CamelliaTest, test_camellia128_ecb) {

    ASSERT_EQ(CAMELLIA128_ECB_KEY.size(), CAMELLIA128_ECB_CIPHER.size());

    for ( unsigned int i = 0; i < CAMELLIA128_ECB_KEY.size(); ++i ) {

        ASSERT_EQ(CAMELLIA_ECB_PLAIN.size(), CAMELLIA128_ECB_CIPHER[i].size());

        auto camellia128 = Camellia(unhexlify(CAMELLIA128_ECB_KEY[i]));
        for ( unsigned int x = 0; x < CAMELLIA_ECB_PLAIN.size(); ++x ) {
            EXPECT_EQ(hexlify(camellia128.encrypt(unhexlify(CAMELLIA_ECB_PLAIN[x]))), CAMELLIA128_ECB_CIPHER[i][x]);
            EXPECT_EQ(hexlify(camellia128.decrypt(unhexlify(CAMELLIA128_ECB_CIPHER[i][x]))), CAMELLIA_ECB_PLAIN[x]);
        }
    }
}

TEST(CamelliaTest, test_camellia192_ecb) {

    ASSERT_EQ(CAMELLIA192_ECB_KEY.size(), CAMELLIA192_ECB_CIPHER.size());

    for ( unsigned int i = 0; i < CAMELLIA192_ECB_KEY.size(); ++i ) {

        ASSERT_EQ(CAMELLIA_ECB_PLAIN.size(), CAMELLIA192_ECB_CIPHER[i].size());

        auto camellia192 = Camellia(unhexlify(CAMELLIA192_ECB_KEY[i]));
        for ( unsigned int x = 0; x < CAMELLIA_ECB_PLAIN.size(); ++x ) {
            EXPECT_EQ(hexlify(camellia192.encrypt(unhexlify(CAMELLIA_ECB_PLAIN[x]))), CAMELLIA192_ECB_CIPHER[i][x]);
            EXPECT_EQ(hexlify(camellia192.decrypt(unhexlify(CAMELLIA192_ECB_CIPHER[i][x]))), CAMELLIA_ECB_PLAIN[x]);
        }
    }
}

TEST(CamelliaTest, test_camellia256_ecb) {

    ASSERT_EQ(CAMELLIA256_ECB_KEY.size(), CAMELLIA256_ECB_CIPHER.size());

    for ( unsigned int i = 0; i < CAMELLIA256_ECB_KEY.size(); ++i ) {

        ASSERT_EQ(CAMELLIA_ECB_PLAIN.size(), CAMELLIA256_ECB_CIPHER[i].size());

        auto camellia256 = Camellia(unhexlify(CAMELLIA256_ECB_KEY[i]));
        for ( unsigned int x = 0; x < CAMELLIA_ECB_PLAIN.size(); ++x ) {
            EXPECT_EQ(hexlify(camellia256.encrypt(unhexlify(CAMELLIA_ECB_PLAIN[x]))), CAMELLIA256_ECB_CIPHER[i][x]);
            EXPECT_EQ(hexlify(camellia256.decrypt(unhexlify(CAMELLIA256_ECB_CIPHER[i][x]))), CAMELLIA_ECB_PLAIN[x]);
        }
    }
}
