#include <gtest/gtest.h>

#include "Hashes/Hashes.h"

#include "testvectors/ripemd/ripemd160testvectors.h"

TEST(RIPEMD, testvectors) {

    ASSERT_EQ(RIPEMD160_MSG.size(), RIPEMD160_MSG_HEXDIGEST.size());

    for ( unsigned int i = 0; i < RIPEMD160_MSG.size(); ++i ) {
        auto ripemd160 = OpenPGP::Hash::use(OpenPGP::Hash::ID::RIPEMD160, unhexlify(RIPEMD160_MSG[i]));
        EXPECT_EQ(hexlify(ripemd160), RIPEMD160_MSG_HEXDIGEST[i]);
    }
}
