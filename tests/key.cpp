#include <gtest/gtest.h>

#include "Key.h"
#include "read_pgp.h"

TEST(Key, Alicepub) {
    OpenPGP::Key key;
    std::string orig;
    ASSERT_TRUE(read_pgp("Alicepub", key, orig, "tests/testvectors/gpg/"));
    EXPECT_EQ(key.write(OpenPGP::PGP::Armored::YES), trim_whitespace(orig, true, true));
}

TEST(PublicKey, Alicepub) {
    OpenPGP::PublicKey key;
    std::string orig;
    ASSERT_TRUE(read_pgp("Alicepub", key, orig, "tests/testvectors/gpg/"));
    EXPECT_EQ(key.write(OpenPGP::PGP::Armored::YES), trim_whitespace(orig, true, true));
}

TEST(Key, Alicepri) {
    OpenPGP::Key key;
    std::string orig;
    ASSERT_TRUE(read_pgp("Alicepri", key, orig, "tests/testvectors/gpg/"));
    EXPECT_EQ(key.write(OpenPGP::PGP::Armored::YES), trim_whitespace(orig, true, true));
}

TEST(SecretKey, Alicepri) {
    OpenPGP::SecretKey key;
    std::string orig;
    ASSERT_TRUE(read_pgp("Alicepri", key, orig, "tests/testvectors/gpg/"));
    EXPECT_EQ(key.write(OpenPGP::PGP::Armored::YES), trim_whitespace(orig, true, true));
}
