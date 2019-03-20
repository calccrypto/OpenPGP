#include <gtest/gtest.h>

#include "Hashes/Hashes.h"

#include "testvectors/sha/sha256shortmsg.h"

TEST(SHA256, short_msg) {

    ASSERT_EQ(SHA256_SHORT_MSG.size(), SHA256_SHORT_MSG_HEXDIGEST.size());

    for ( unsigned int i = 0; i < SHA256_SHORT_MSG.size(); ++i ) {
        auto sha256 = OpenPGP::Hash::use(OpenPGP::Hash::ID::SHA256, unhexlify(SHA256_SHORT_MSG[i]));
        EXPECT_EQ(hexlify(sha256), SHA256_SHORT_MSG_HEXDIGEST[i]);
    }
}

