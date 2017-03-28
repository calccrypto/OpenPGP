#include <gtest/gtest.h>

#include "Hashes/SHA224.h"

#include "testvectors/sha/sha224shortmsg.h"

TEST(SHA224, short_msg) {

    ASSERT_EQ(SHA224_SHORT_MSG.size(), SHA224_SHORT_MSG_HEXDIGEST.size());

    for ( unsigned int i = 0; i < SHA224_SHORT_MSG.size(); ++i ) {
        auto sha224 = SHA224(unhexlify(SHA224_SHORT_MSG[i]));
        EXPECT_EQ(sha224.hexdigest(), SHA224_SHORT_MSG_HEXDIGEST[i]);
    }
}
