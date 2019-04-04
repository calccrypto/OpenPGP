#include <gtest/gtest.h>

#include "Message.h"
#include "pgp_macro.h"

static const std::string dir = "tests/testvectors/gpg/";

TEST(Message, pkaencrypted) {
    TEST_PGP(OpenPGP::Message, dir + "pkaencrypted");
}

TEST(Message, pkaencryptednomdc) {
    TEST_PGP(OpenPGP::Message, dir + "pkaencryptednomdc");
}

TEST(Message, symencrypted) {
    TEST_PGP(OpenPGP::Message, dir + "symencrypted");
}

TEST(Message, symencryptednomdc) {
    TEST_PGP(OpenPGP::Message, dir + "symencryptednomdc");
}

// // fails because partial body lengths are written differently
// TEST(Message, signature) {
//     TEST_PGP(OpenPGP::Message, dir + "signature");
// }
