#include <gtest/gtest.h>

#include <fstream>

#include "Message.h"
#include "pgp_macro.h"

static const std::string dir = "tests/testvectors/gpg/";

TEST(Message, Constructor) {
    std::ifstream file(dir + "pkaencrypted");
    ASSERT_TRUE(file);

    const std::string orig = trim_whitespace(std::string(std::istreambuf_iterator <char> (file), {}), true, true);
    file.seekg(0);

    // Default constructor
    OpenPGP::Message msg;
    EXPECT_NO_THROW(msg.read(orig));
    EXPECT_TRUE(msg.meaningful());

    // PGP Copy Constructor
    {
        OpenPGP::Message copy((OpenPGP::PGP) msg);
        EXPECT_EQ(orig, copy.write());
    }

    // Copy Constructor
    {
        OpenPGP::Message copy(msg);
        EXPECT_EQ(orig, copy.write());
    }

    // Move Constructor
    {
        OpenPGP::Message move(std::move(msg));
        EXPECT_EQ(orig, move.write());
    }

    // String Constructor
    {
        OpenPGP::Message str(orig);
        EXPECT_EQ(orig, str.write());
    }

    // Stream Constructor
    {
        OpenPGP::Message stream(file);
        EXPECT_EQ(orig, stream.write());
    }
}

TEST(Message, Assignment) {
    std::ifstream file(dir + "pkaencrypted");
    ASSERT_TRUE(file);

    OpenPGP::Message msg(file);
    EXPECT_TRUE(msg.meaningful());

    file.seekg(0);

    const std::string orig = trim_whitespace(std::string(std::istreambuf_iterator <char> (file), {}), true, true);

    // Assignment
    {
        OpenPGP::Message copy;
        copy = msg;
        EXPECT_EQ(orig, copy.write());
    }

    // Move Assignment
    {
        OpenPGP::Message move;
        move = std::move(msg);
        EXPECT_EQ(orig, move.write());
    }
}

TEST(Message, show) {
    std::ifstream file(dir + "pkaencrypted");
    ASSERT_TRUE(file);

    OpenPGP::Message msg(file);
    EXPECT_TRUE(msg.meaningful());

    EXPECT_NO_THROW(msg.show());
}

TEST(Message, clone) {
    std::ifstream file(dir + "pkaencrypted");
    ASSERT_TRUE(file);

    OpenPGP::Message msg(file);
    EXPECT_TRUE(msg.meaningful());

    OpenPGP::Message::Ptr clone = std::dynamic_pointer_cast <OpenPGP::Message> (msg.clone());
    EXPECT_EQ(msg.write(), clone -> write());
}

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
