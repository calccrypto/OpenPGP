#include <gtest/gtest.h>

#include "Hashes/SHA384.h"

#include "testvectors/sha/sha384shortmsg.h"

TEST(SHA384, short_msg) {

    ASSERT_EQ(SHA384_SHORT_MSG.size(), SHA384_SHORT_MSG_HEXDIGEST.size());

    for ( unsigned int i = 0; i < SHA384_SHORT_MSG.size(); ++i ) {
        auto sha384 = SHA384(unhexlify(SHA384_SHORT_MSG[i]));
        EXPECT_EQ(sha384.hexdigest(), SHA384_SHORT_MSG_HEXDIGEST[i]);
    }
}


