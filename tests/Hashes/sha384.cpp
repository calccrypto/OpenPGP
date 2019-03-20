#include <gtest/gtest.h>

#include "Hashes/Hashes.h"

#include "testvectors/sha/sha384shortmsg.h"

TEST(SHA384, short_msg) {

    ASSERT_EQ(SHA384_SHORT_MSG.size(), SHA384_SHORT_MSG_HEXDIGEST.size());

    for ( unsigned int i = 0; i < SHA384_SHORT_MSG.size(); ++i ) {
        auto sha384 = OpenPGP::Hash::use(OpenPGP::Hash::ID::SHA384, unhexlify(SHA384_SHORT_MSG[i]));
        EXPECT_EQ(hexlify(sha384), SHA384_SHORT_MSG_HEXDIGEST[i]);
    }
}


