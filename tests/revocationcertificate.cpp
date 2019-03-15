#include <gtest/gtest.h>

#include "RevocationCertificate.h"
#include "read_pgp.h"

TEST(RevocationCertificate, revoke) {
    OpenPGP::RevocationCertificate msg;
    std::string orig;
    ASSERT_TRUE(read_pgp("revoke", msg, orig, "tests/testvectors/gpg/"));
    EXPECT_EQ(msg.write(OpenPGP::PGP::Armored::YES), trim_whitespace(orig, true, true));
}
