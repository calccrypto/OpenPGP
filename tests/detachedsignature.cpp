#include <gtest/gtest.h>

#include <fstream>

#include "DetachedSignature.h"

static const std::string filename = "tests/testvectors/gpg/detached";

TEST(DetachedSignature, Constructor) {
    std::ifstream file(filename);
    ASSERT_TRUE(file);

    const std::string orig = trim_whitespace(std::string(std::istreambuf_iterator <char> (file), {}), true, true);
    file.seekg(0);

    // Default constructor
    OpenPGP::DetachedSignature msg;
    EXPECT_NO_THROW(msg.read(orig));
    EXPECT_TRUE(msg.meaningful());

    // PGP Copy Constructor
    {
        OpenPGP::DetachedSignature copy((OpenPGP::PGP) msg);
        EXPECT_EQ(orig, copy.write());
    }

    // Copy Constructor
    {
        OpenPGP::DetachedSignature copy(msg);
        EXPECT_EQ(orig, copy.write());
    }

    // Move Constructor
    {
        OpenPGP::DetachedSignature move(std::move(msg));
        EXPECT_EQ(orig, move.write());
    }

    // String Constructor
    {
        OpenPGP::DetachedSignature str(orig);
        EXPECT_EQ(orig, str.write());
    }

    // Stream Constructor
    {
        OpenPGP::DetachedSignature stream(file);
        EXPECT_EQ(orig, stream.write());
    }
}

TEST(DetachedSignature, Assignment) {
    std::ifstream file(filename);
    ASSERT_TRUE(file);

    OpenPGP::DetachedSignature msg(file);
    EXPECT_TRUE(msg.meaningful());

    file.seekg(0);

    const std::string orig = trim_whitespace(std::string(std::istreambuf_iterator <char> (file), {}), true, true);

    // Assignment
    {
        OpenPGP::DetachedSignature copy;
        copy = msg;
        EXPECT_EQ(orig, copy.write());
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

    OpenPGP::DetachedSignature::Ptr clone = std::dynamic_pointer_cast <OpenPGP::DetachedSignature> (msg.clone());
    EXPECT_EQ(msg.write(), clone -> write());
}
