#include <gtest/gtest.h>

#include "Hashes/SHA1.h"

#include "testvectors/sha/sha1shortmsg.h"

TEST(SHA1, short_msg) {

    ASSERT_EQ(SHA1_SHORT_MSG.size(), SHA1_SHORT_MSG_HEXDIGEST.size());

    for ( unsigned int i = 0; i < SHA1_SHORT_MSG.size(); ++i ) {
        auto sha1 = SHA1(unhexlify(SHA1_SHORT_MSG[i]));
        EXPECT_EQ(sha1.hexdigest(), SHA1_SHORT_MSG_HEXDIGEST[i]);
    }
}
