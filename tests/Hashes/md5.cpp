#include <gtest/gtest.h>

#include "Hashes/Hashes.h"

#include "testvectors/md5/md5testvectors.h"

TEST(MD5, vectors) {

    ASSERT_EQ(MD5_BYTES.size(), MD5_HASHES.size());

    for ( unsigned int i = 0; i < MD5_BYTES.size(); ++i ) {
        auto md5 = OpenPGP::Hash::use(OpenPGP::Hash::ID::MD5, unhexlify(MD5_BYTES[i]));
        EXPECT_EQ(hexlify(md5), MD5_HASHES[i]);
    }
}
