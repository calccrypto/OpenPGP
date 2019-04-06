#include <gtest/gtest.h>

#include <fstream>

#include "CleartextSignature.h"

static const std::string filename = "tests/testvectors/gpg/clearsign";

TEST(CleartextSignature, Constructor) {
    std::ifstream file(filename);
    ASSERT_TRUE(file);

    // Default constructor
    OpenPGP::CleartextSignature msg;
    EXPECT_NO_THROW(msg.read(file));
    EXPECT_TRUE(msg.meaningful());

    const std::string orig = msg.write();

    // Copy Constructor
    {
        OpenPGP::CleartextSignature copy(msg);
        EXPECT_EQ(msg, copy);
    }

    // String Constructor
    {
        OpenPGP::CleartextSignature str(orig);
        EXPECT_EQ(msg, str);
    }

    // Stream Constructor
    {
        file.seekg(0);

        OpenPGP::CleartextSignature stream(file);
        EXPECT_EQ(msg, stream);
    }

    // Move Constructor
    {
        OpenPGP::CleartextSignature move(std::move(msg));
        EXPECT_EQ(orig, move.write());
    }
}

TEST(CleartextSignature, Assignment) {
    std::ifstream file(filename);
    ASSERT_TRUE(file);

    OpenPGP::CleartextSignature msg(file);
    EXPECT_TRUE(msg.meaningful());

    const std::string orig = msg.write();

    // Assignment
    {
        OpenPGP::CleartextSignature copy;
        copy = msg;
        EXPECT_EQ(msg, copy);
    }

    // Move Assignment
    {
        OpenPGP::CleartextSignature move;
        move = std::move(msg);
        EXPECT_EQ(orig, move.write());
    }
}

TEST(CleartextSignature, show) {
    std::ifstream file(filename);
    ASSERT_TRUE(file);

    OpenPGP::CleartextSignature msg(file);
    EXPECT_TRUE(msg.meaningful());

    EXPECT_NO_THROW(msg.show());
}

TEST(CleartextSignature, clone) {
    std::ifstream file(filename);
    ASSERT_TRUE(file);

    OpenPGP::CleartextSignature msg(file);
    EXPECT_TRUE(msg.meaningful());

    EXPECT_EQ(msg, *msg.clone());
}
