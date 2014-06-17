#include <gtest/gtest.h>

#include "Hashes/MD5.h"

#include "testvectors/md5/md5vectors.h"

TEST(MD5Test, test_md5_vectors) {

    ASSERT_EQ(MD5_BYTES.size(), MD5_HASHES.size());

    for ( unsigned int i = 0; i < MD5_BYTES.size(); ++i ) {
        auto md5 = MD5(unhexlify(MD5_BYTES[i]));
        EXPECT_EQ(md5.hexdigest(), MD5_HASHES[i]);
    }
}
