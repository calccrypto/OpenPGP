#include <gtest/gtest.h>

#include "Encryptions/Blowfish.h"

#include "testvectors/blowfish/blowfishtestvectors.h"

TEST(BlowfishTest, test_blowfish_ecb) {

    ASSERT_EQ(BLOWFISH_ECB_KEY.size(), BLOWFISH_ECB_PLAIN.size());
    ASSERT_EQ(BLOWFISH_ECB_PLAIN.size(), BLOWFISH_ECB_CIPHER.size());

    for ( unsigned int i = 0; i < BLOWFISH_ECB_KEY.size(); ++i ) {
        auto blowfish = Blowfish(unhexlify(BLOWFISH_ECB_KEY[i]));
        EXPECT_EQ(hexlify(blowfish.encrypt(unhexlify(BLOWFISH_ECB_PLAIN[i]))), BLOWFISH_ECB_CIPHER[i]);
        EXPECT_EQ(hexlify(blowfish.decrypt(unhexlify(BLOWFISH_ECB_CIPHER[i]))), BLOWFISH_ECB_PLAIN[i]);
    }
}


