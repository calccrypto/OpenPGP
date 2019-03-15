#include <gtest/gtest.h>

#include "Message.h"
#include "read_pgp.h"

TEST(Message, pkaencrypted) {
    OpenPGP::Message msg;
    std::string orig;
    ASSERT_TRUE(read_pgp("pkaencrypted", msg, orig, "tests/testvectors/gpg/"));
    EXPECT_EQ(msg.write(OpenPGP::PGP::Armored::YES), trim_whitespace(orig, true, true));
}

TEST(Message, pkaencryptednomdc) {
    OpenPGP::Message msg;
    std::string orig;
    ASSERT_TRUE(read_pgp("pkaencryptednomdc", msg, orig, "tests/testvectors/gpg/"));
    EXPECT_EQ(msg.write(OpenPGP::PGP::Armored::YES), trim_whitespace(orig, true, true));
}

TEST(Message, symencrypted) {
    OpenPGP::Message msg;
    std::string orig;
    ASSERT_TRUE(read_pgp("symencrypted", msg, orig, "tests/testvectors/gpg/"));
    EXPECT_EQ(msg.write(OpenPGP::PGP::Armored::YES), trim_whitespace(orig, true, true));
}

TEST(Message, symencryptednomdc) {
    OpenPGP::Message msg;
    std::string orig;
    ASSERT_TRUE(read_pgp("symencryptednomdc", msg, orig, "tests/testvectors/gpg/"));
    EXPECT_EQ(msg.write(OpenPGP::PGP::Armored::YES), trim_whitespace(orig, true, true));
}

// // fails because partial body lengths are written differently
// TEST(Message, signature) {
//     OpenPGP::Message msg;
//     std::string orig;
//     ASSERT_TRUE(read_pgp("signature", msg, orig, "tests/testvectors/gpg/"));
//     EXPECT_EQ(msg.write(OpenPGP::PGP::Armored::YES), trim_whitespace(orig, true, true));
// }
