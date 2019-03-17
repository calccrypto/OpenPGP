#include <gtest/gtest.h>

#include "Hashes/Hashes.h"

#include "testvectors/sha/sha224shortmsg.h"

TEST(SHA224, short_msg) {

    ASSERT_EQ(SHA224_SHORT_MSG.size(), SHA224_SHORT_MSG_HEXDIGEST.size());

    for ( unsigned int i = 0; i < SHA224_SHORT_MSG.size(); ++i ) {
        auto sha224 = OpenPGP::Hash::use(OpenPGP::Hash::ID::SHA224, unhexlify(SHA224_SHORT_MSG[i]));
        EXPECT_EQ(hexlify(sha224), SHA224_SHORT_MSG_HEXDIGEST[i]);
    }
}
