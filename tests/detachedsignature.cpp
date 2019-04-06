#include <gtest/gtest.h>

#include <fstream>

#include "DetachedSignature.h"

static const std::string filename = "tests/testvectors/gpg/detached";

TEST(DetachedSignature, Constructor) {
    std::ifstream file(filename);
    ASSERT_TRUE(file);

    // Default constructor
    OpenPGP::DetachedSignature msg;
    EXPECT_NO_THROW(msg.read(file));
    EXPECT_TRUE(msg.meaningful());

    const std::string orig = msg.write();

    // PGP Copy Constructor
    {
        OpenPGP::DetachedSignature copy((OpenPGP::PGP) msg);
        EXPECT_EQ(msg, copy);
    }

    // Copy Constructor
    {
        OpenPGP::DetachedSignature copy(msg);
        EXPECT_EQ(msg, copy);
    }

    // String Constructor
    {
        OpenPGP::DetachedSignature str(orig);
        EXPECT_EQ(msg, str);
    }

    // Stream Constructor
    {
        file.seekg(0);

        OpenPGP::DetachedSignature stream(file);
        EXPECT_EQ(msg, stream);
    }

    // Move Constructor
    {
        OpenPGP::DetachedSignature move(std::move(msg));
        EXPECT_EQ(orig, move.write());
    }
}

TEST(DetachedSignature, Assignment) {
    std::ifstream file(filename);
    ASSERT_TRUE(file);

    OpenPGP::DetachedSignature msg(file);
    EXPECT_TRUE(msg.meaningful());

    const std::string orig = msg.write();

    // Assignment
    {
        OpenPGP::DetachedSignature copy;
        copy = msg;
        EXPECT_EQ(msg, copy);
    }

    // Move Assignment
    {
        OpenPGP::DetachedSignature move;
        move = std::move(msg);
        EXPECT_EQ(orig, move.write());
    }
}

TEST(DetachedSignature, show) {
    std::ifstream file(filename);
    ASSERT_TRUE(file);

    OpenPGP::DetachedSignature msg(file);
    EXPECT_TRUE(msg.meaningful());

    EXPECT_NO_THROW(msg.show());
}

TEST(DetachedSignature, clone) {
    std::ifstream file(filename);
    ASSERT_TRUE(file);

    OpenPGP::DetachedSignature msg(file);
    EXPECT_TRUE(msg.meaningful());

    EXPECT_EQ(msg, *msg.clone());
}
