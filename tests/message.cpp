#include <gtest/gtest.h>

#include <fstream>

#include "Message.h"

static const std::string dir = "tests/testvectors/gpg/";

TEST(Message, Constructor) {
    std::ifstream file(dir + "pkaencrypted");
    ASSERT_TRUE(file);

    // Default constructor
    OpenPGP::Message msg;
    EXPECT_NO_THROW(msg.read(file));
    EXPECT_TRUE(msg.meaningful());

    const std::string orig = msg.write();

    // PGP Copy Constructor
    {
        OpenPGP::Message copy((OpenPGP::PGP) msg);
        EXPECT_EQ(msg, copy);
    }

    // Copy Constructor
    {
        OpenPGP::Message copy(msg);
        EXPECT_EQ(msg, copy);
    }

    // String Constructor
    {
        OpenPGP::Message str(orig);
        EXPECT_EQ(msg, str);
    }

    // Stream Constructor
    {
        file.seekg(0);

        OpenPGP::Message stream(file);
        EXPECT_EQ(msg, stream);
    }

    // Move Constructor
    {
        OpenPGP::Message move(std::move(msg));
        EXPECT_EQ(orig, move.write());
    }
}

TEST(Message, Assignment) {
    std::ifstream file(dir + "pkaencrypted");
    ASSERT_TRUE(file);

    OpenPGP::Message msg(file);
    EXPECT_TRUE(msg.meaningful());

    const std::string orig = msg.write();

    // Assignment
    {
        OpenPGP::Message copy;
        copy = msg;
        EXPECT_EQ(msg, copy);
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

    EXPECT_EQ(msg, *msg.clone());
}

TEST(Message, pkaencrypted) {
    std::ifstream file(dir + "pkaencrypted");
    ASSERT_TRUE(file);

    OpenPGP::Message msg(file);
    EXPECT_TRUE(msg.meaningful());

    file.seekg(0);
    const std::string orig = trim_whitespace(std::string(std::istreambuf_iterator <char> (file), {}), true, true);
    EXPECT_EQ(msg.write(), orig);
}

TEST(Message, pkaencryptednomdc) {
    std::ifstream file(dir + "pkaencryptednomdc");
    ASSERT_TRUE(file);

    OpenPGP::Message msg(file);
    EXPECT_TRUE(msg.meaningful());

    file.seekg(0);
    const std::string orig = trim_whitespace(std::string(std::istreambuf_iterator <char> (file), {}), true, true);
    EXPECT_EQ(msg.write(), orig);
}

TEST(Message, symencrypted) {
    std::ifstream file(dir + "symencrypted");
    ASSERT_TRUE(file);

    OpenPGP::Message msg(file);
    EXPECT_TRUE(msg.meaningful());

    file.seekg(0);
    const std::string orig = trim_whitespace(std::string(std::istreambuf_iterator <char> (file), {}), true, true);
    EXPECT_EQ(msg.write(), orig);
}

TEST(Message, symencryptednomdc) {
    std::ifstream file(dir + "symencryptednomdc");
    ASSERT_TRUE(file);

    OpenPGP::Message msg(file);
    EXPECT_TRUE(msg.meaningful());

    file.seekg(0);
    const std::string orig = trim_whitespace(std::string(std::istreambuf_iterator <char> (file), {}), true, true);
    EXPECT_EQ(msg.write(), orig);
}

TEST(Message, signature) {
    std::ifstream file(dir + "signature");
    ASSERT_TRUE(file);

    OpenPGP::Message msg(file);
    EXPECT_TRUE(msg.meaningful());

    // This fails because partial packets are written differently
    // file.seekg(0);
    // const std::string orig = trim_whitespace(std::string(std::istreambuf_iterator <char> (file), {}), true, true);
    // EXPECT_EQ(msg.write(), orig);
}
