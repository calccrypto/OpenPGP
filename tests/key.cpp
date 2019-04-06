#include <gtest/gtest.h>

#include "Key.h"
#include "pgp_macro.h"

static const std::string dir = "tests/testvectors/gpg/";

TEST(Key, Constructor) {
    std::ifstream file(dir + "Alicepri");
    ASSERT_TRUE(file);

    const std::string orig = trim_whitespace(std::string(std::istreambuf_iterator <char> (file), {}), true, true);
    file.seekg(0);

    // Default constructor
    OpenPGP::Key key;
    EXPECT_NO_THROW(key.read(orig));
    EXPECT_TRUE(key.meaningful());

    // PGP Copy Constructor
    {
        OpenPGP::Key copy((OpenPGP::PGP) key);
        EXPECT_EQ(orig, copy.write());
    }

    // Copy Constructor
    {
        OpenPGP::Key copy(key);
        EXPECT_EQ(orig, copy.write());
    }

    // Move Constructor
    {
        OpenPGP::Key move(std::move(key));
        EXPECT_EQ(orig, move.write());
    }

    // String Constructor
    {
        OpenPGP::Key str(orig);
        EXPECT_EQ(orig, str.write());
    }

    // Stream Constructor
    {
        OpenPGP::Key stream(file);
        EXPECT_EQ(orig, stream.write());
    }
}

TEST(Key, Assignment) {
    std::ifstream file(dir + "Alicepri");
    ASSERT_TRUE(file);

    OpenPGP::Key key(file);
    EXPECT_TRUE(key.meaningful());

    file.seekg(0);

    const std::string orig = trim_whitespace(std::string(std::istreambuf_iterator <char> (file), {}), true, true);

    // Assignment
    {
        OpenPGP::Key copy;
        copy = key;
        EXPECT_EQ(orig, copy.write());
    }

    // Move Assignment
    {
        OpenPGP::Key move;
        move = std::move(key);
        EXPECT_EQ(orig, move.write());
    }
}

TEST(Key, show) {
    std::ifstream file(dir + "Alicepri");
    ASSERT_TRUE(file);

    OpenPGP::Key key(file);
    EXPECT_TRUE(key.meaningful());

    EXPECT_NO_THROW(key.show());
}

TEST(Key, clone) {
    std::ifstream file(dir + "Alicepri");
    ASSERT_TRUE(file);

    OpenPGP::Key key(file);
    EXPECT_TRUE(key.meaningful());

    OpenPGP::Key::Ptr clone = std::dynamic_pointer_cast <OpenPGP::Key> (key.clone());
    EXPECT_EQ(key.write(), clone -> write());
}

TEST(PublicKey, Constructor) {
    std::ifstream file(dir + "Alicepub");
    ASSERT_TRUE(file);

    const std::string orig = trim_whitespace(std::string(std::istreambuf_iterator <char> (file), {}), true, true);
    file.seekg(0);

    // Default constructor
    OpenPGP::PublicKey key;
    EXPECT_NO_THROW(key.read(orig));
    EXPECT_TRUE(key.meaningful());

    // PGP Copy Constructor
    {
        OpenPGP::PublicKey copy((OpenPGP::PGP) key);
        EXPECT_EQ(orig, copy.write());
    }

    // Copy Constructor
    {
        OpenPGP::PublicKey copy(key);
        EXPECT_EQ(orig, copy.write());
    }

    // Move Constructor
    {
        OpenPGP::PublicKey move(std::move(key));
        EXPECT_EQ(orig, move.write());
    }

    // String Constructor
    {
        OpenPGP::PublicKey str(orig);
        EXPECT_EQ(orig, str.write());
    }

    // Stream Constructor
    {
        OpenPGP::PublicKey stream(file);
        EXPECT_EQ(orig, stream.write());
    }
}

TEST(PublicKey, Assignment) {
    std::ifstream file(dir + "Alicepub");
    ASSERT_TRUE(file);

    OpenPGP::PublicKey key(file);
    EXPECT_TRUE(key.meaningful());

    file.seekg(0);

    const std::string orig = trim_whitespace(std::string(std::istreambuf_iterator <char> (file), {}), true, true);

    // Assignment
    {
        OpenPGP::PublicKey copy;
        copy = key;
        EXPECT_EQ(orig, copy.write());
    }

    // Move Assignment
    {
        OpenPGP::PublicKey move;
        move = std::move(key);
        EXPECT_EQ(orig, move.write());
    }
}

TEST(PublicKey, show) {
    std::ifstream file(dir + "Alicepub");
    ASSERT_TRUE(file);

    OpenPGP::PublicKey key(file);
    EXPECT_TRUE(key.meaningful());

    EXPECT_NO_THROW(key.show());
}

TEST(PublicKey, clone) {
    std::ifstream file(dir + "Alicepub");
    ASSERT_TRUE(file);

    OpenPGP::PublicKey key(file);
    EXPECT_TRUE(key.meaningful());

    OpenPGP::PublicKey::Ptr clone = std::dynamic_pointer_cast <OpenPGP::PublicKey> (key.clone());
    EXPECT_EQ(key.write(), clone -> write());
}

TEST(Key, Alicepub) {
    TEST_PGP(OpenPGP::Key, dir + "Alicepub");
}

TEST(PublicKey, Alicepub) {
    TEST_PGP(OpenPGP::PublicKey, dir + "Alicepub");
}

TEST(SecretKey, AlicePub) {
    std::ifstream file(dir + "Alicepub");
    ASSERT_TRUE(file);

    OpenPGP::SecretKey key(file);
    EXPECT_FALSE(key.meaningful());
}

TEST(SecretKey, Constructor) {
    std::ifstream file(dir + "Alicepri");
    ASSERT_TRUE(file);

    const std::string orig = trim_whitespace(std::string(std::istreambuf_iterator <char> (file), {}), true, true);
    file.seekg(0);

    // Default constructor
    OpenPGP::SecretKey key;
    EXPECT_NO_THROW(key.read(orig));
    EXPECT_TRUE(key.meaningful());

    // PGP Copy Constructor
    {
        OpenPGP::SecretKey copy((OpenPGP::PGP) key);
        EXPECT_EQ(orig, copy.write());
    }

    // Copy Constructor
    {
        OpenPGP::SecretKey copy(key);
        EXPECT_EQ(orig, copy.write());
    }

    // Move Constructor
    {
        OpenPGP::SecretKey move(std::move(key));
        EXPECT_EQ(orig, move.write());
    }

    // String Constructor
    {
        OpenPGP::SecretKey str(orig);
        EXPECT_EQ(orig, str.write());
    }

    // Stream Constructor
    {
        OpenPGP::SecretKey stream(file);
        EXPECT_EQ(orig, stream.write());
    }
}

TEST(SecretKey, Assignment) {
    std::ifstream file(dir + "Alicepri");
    ASSERT_TRUE(file);

    OpenPGP::SecretKey key(file);
    EXPECT_TRUE(key.meaningful());

    file.seekg(0);

    const std::string orig = trim_whitespace(std::string(std::istreambuf_iterator <char> (file), {}), true, true);

    // Assignment
    {
        OpenPGP::SecretKey copy;
        copy = key;
        EXPECT_EQ(orig, copy.write());
    }

    // Move Assignment
    {
        OpenPGP::SecretKey move;
        move = std::move(key);
        EXPECT_EQ(orig, move.write());
    }
}

TEST(SecretKey, show) {
    std::ifstream file(dir + "Alicepri");
    ASSERT_TRUE(file);

    OpenPGP::SecretKey key(file);
    EXPECT_TRUE(key.meaningful());

    EXPECT_NO_THROW(key.show());
}

TEST(SecretKey, clone) {
    std::ifstream file(dir + "Alicepri");
    ASSERT_TRUE(file);

    OpenPGP::SecretKey key(file);
    EXPECT_TRUE(key.meaningful());

    OpenPGP::SecretKey::Ptr clone = std::dynamic_pointer_cast <OpenPGP::SecretKey> (key.clone());
    EXPECT_EQ(key.write(), clone -> write());
}

TEST(Key, Alicepri) {
    TEST_PGP(OpenPGP::Key, dir + "Alicepri");
}

TEST(PublicKey, AlicePri) {
    std::ifstream file(dir + "Alicepri");
    ASSERT_TRUE(file);

    OpenPGP::PublicKey key(file);
    EXPECT_FALSE(key.meaningful());
}

TEST(SecretKey, Alicepri) {
    TEST_PGP(OpenPGP::SecretKey, dir + "Alicepri");
}
