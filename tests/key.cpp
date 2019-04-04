#include <gtest/gtest.h>

#include "Key.h"
#include "pgp_macro.h"

TEST(Key, Alicepub) {
    TEST_PGP(OpenPGP::Key,       "tests/testvectors/gpg/Alicepub");
}

TEST(PublicKey, Alicepub) {
    TEST_PGP(OpenPGP::PublicKey, "tests/testvectors/gpg/Alicepub");
}

TEST(Key, Alicepri) {
    TEST_PGP(OpenPGP::Key,       "tests/testvectors/gpg/Alicepri");
}

TEST(SecretKey, Alicepri) {
    TEST_PGP(OpenPGP::SecretKey, "tests/testvectors/gpg/Alicepri");
}
