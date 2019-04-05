#include <gtest/gtest.h>

#include <fstream>

#include "CleartextSignature.h"

static const std::string filename = "tests/testvectors/gpg/clearsign";

TEST(CleartextSignature, Constructor) {
    std::ifstream file(filename);
    ASSERT_TRUE(file);

    const std::string orig = trim_whitespace(std::string(std::istreambuf_iterator <char> (file), {}), true, true);
    file.seekg(0);

    // Default constructor
    OpenPGP::CleartextSignature msg;
    EXPECT_NO_THROW(msg.read(orig));
    EXPECT_TRUE(msg.meaningful());

    // Copy Constructor
    {
        OpenPGP::CleartextSignature copy(msg);
        EXPECT_EQ(orig, copy.write());
    }

    // Move Constructor
    {
        OpenPGP::CleartextSignature move(std::move(msg));
        EXPECT_EQ(orig, move.write());
    }

    // String Constructor
    {
        OpenPGP::CleartextSignature str(orig);
        EXPECT_EQ(orig, str.write());
    }

    // Stream Constructor
    {
        OpenPGP::CleartextSignature stream(file);
        EXPECT_EQ(orig, stream.write());
    }
}

TEST(CleartextSignature, Assignment) {
    std::ifstream file(filename);
    ASSERT_TRUE(file);

    OpenPGP::CleartextSignature msg(file);
    EXPECT_TRUE(msg.meaningful());

    file.seekg(0);

    const std::string orig = trim_whitespace(std::string(std::istreambuf_iterator <char> (file), {}), true, true);

    // Assignment
    {
        OpenPGP::CleartextSignature copy;
        copy = msg;
        EXPECT_EQ(orig, copy.write());
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

    OpenPGP::CleartextSignature::Ptr clone = msg.clone();
    EXPECT_EQ(msg.write(), clone -> write());
}
