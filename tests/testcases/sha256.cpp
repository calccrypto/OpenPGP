#include <gtest/gtest.h>

#include "Hashes/SHA256.h"

#include "testvectors/sha/sha256shortmsg.h"

TEST(SHA256, short_msg) {

    ASSERT_EQ(SHA256_SHORT_MSG.size(), SHA256_SHORT_MSG_HEXDIGEST.size());

    for ( unsigned int i = 0; i < SHA256_SHORT_MSG.size(); ++i ) {
        auto sha256 = SHA256(unhexlify(SHA256_SHORT_MSG[i]));
        EXPECT_EQ(sha256.hexdigest(), SHA256_SHORT_MSG_HEXDIGEST[i]);
    }
}

