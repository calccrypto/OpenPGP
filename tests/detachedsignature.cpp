#include <gtest/gtest.h>

#include "DetachedSignature.h"
#include "read_pgp.h"

TEST(DetachedSignature, detached) {
    OpenPGP::DetachedSignature msg;
    std::string orig;
    ASSERT_TRUE(read_pgp("detached", msg, orig, "tests/testvectors/gpg/"));
    EXPECT_EQ(msg.write(OpenPGP::PGP::Armored::YES), trim_whitespace(orig, true, true));
}
