#include <gtest/gtest.h>

#include "CleartextSignature.h"
#include "read_pgp.h"

TEST(CleartextSignature, clearsign) {
    OpenPGP::CleartextSignature msg;
    std::string orig;
    ASSERT_TRUE(read_pgp("clearsign", msg, orig, "tests/testvectors/gpg/"));
    EXPECT_EQ(msg.write(), trim_whitespace(orig, true, true));
}
