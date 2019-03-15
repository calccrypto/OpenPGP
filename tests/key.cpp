#include <gtest/gtest.h>

#include "Key.h"
#include "read_pgp.h"

TEST(Key, Alicepub) {
    OpenPGP::Key msg;
    std::string orig;
    ASSERT_TRUE(read_pgp("Alicepub", msg, orig, "tests/testvectors/gpg/"));
    EXPECT_EQ(msg.write(OpenPGP::PGP::Armored::YES), trim_whitespace(orig, true, true));
}

TEST(PublicKey, Alicepub) {
    OpenPGP::PublicKey msg;
    std::string orig;
    ASSERT_TRUE(read_pgp("Alicepub", msg, orig, "tests/testvectors/gpg/"));
    EXPECT_EQ(msg.write(OpenPGP::PGP::Armored::YES), trim_whitespace(orig, true, true));
}

TEST(Key, Alicepri) {
    OpenPGP::Key msg;
    std::string orig;
    ASSERT_TRUE(read_pgp("Alicepri", msg, orig, "tests/testvectors/gpg/"));
    EXPECT_EQ(msg.write(OpenPGP::PGP::Armored::YES), trim_whitespace(orig, true, true));
}

TEST(SecretKey, Alicepri) {
    OpenPGP::SecretKey msg;
    std::string orig;
    ASSERT_TRUE(read_pgp("Alicepri", msg, orig, "tests/testvectors/gpg/"));
    EXPECT_EQ(msg.write(OpenPGP::PGP::Armored::YES), trim_whitespace(orig, true, true));
}
