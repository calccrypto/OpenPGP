#include <gtest/gtest.h>

#include <fstream>

#include "Key.h"

static const std::string dir = "tests/testvectors/gpg/";

TEST(Key, Constructor) {
    std::ifstream file(dir + "Alicepri");
    ASSERT_TRUE(file);

    // Default constructor
    OpenPGP::Key key;
    EXPECT_NO_THROW(key.read(file));
    EXPECT_TRUE(key.meaningful());

    const std::string orig = key.write();

    // PGP Copy Constructor
    {
        OpenPGP::Key copy((OpenPGP::PGP) key);
        EXPECT_EQ(key, copy.write());
    }

    // Copy Constructor
    {
        OpenPGP::Key copy(key);
        EXPECT_EQ(key, copy.write());
    }

    // String Constructor
    {
        OpenPGP::Key str(orig);
        EXPECT_EQ(key, str.write());
    }

    // Stream Constructor
    {
        file.seekg(0);

        OpenPGP::Key stream(file);
        EXPECT_EQ(key, stream);
    }

    // Move Constructor
    {
        OpenPGP::Key move(std::move(key));
        EXPECT_EQ(orig, move.write());
    }
}

TEST(Key, Assignment) {
    std::ifstream file(dir + "Alicepri");
    ASSERT_TRUE(file);

    OpenPGP::Key key(file);
    EXPECT_TRUE(key.meaningful());

    const std::string orig = key.write();

    // Assignment
    {
        OpenPGP::Key copy;
        copy = key;
        EXPECT_EQ(key, copy);
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

    EXPECT_EQ(key, *key.clone());
}

TEST(PublicKey, Constructor) {
    std::ifstream file(dir + "Alicepub");
    ASSERT_TRUE(file);

    // Default constructor
    OpenPGP::PublicKey key;
    EXPECT_NO_THROW(key.read(file));
    EXPECT_TRUE(key.meaningful());

    const std::string orig = key.write();

    // PGP Copy Constructor
    {
        OpenPGP::PublicKey copy((OpenPGP::PGP) key);
        EXPECT_EQ(key, copy);
    }

    // Copy Constructor
    {
        OpenPGP::PublicKey copy(key);
        EXPECT_EQ(key, copy);
    }

    // String Constructor
    {
        OpenPGP::PublicKey str(orig);
        EXPECT_EQ(orig, str.write());
    }

    // Stream Constructor
    {
        file.seekg(0);

        OpenPGP::PublicKey stream(file);
        EXPECT_EQ(key, stream);
    }

    // Move Constructor
    {
        OpenPGP::PublicKey move(std::move(key));
        EXPECT_EQ(orig, move.write());
    }
}

TEST(PublicKey, Assignment) {
    std::ifstream file(dir + "Alicepub");
    ASSERT_TRUE(file);

    OpenPGP::PublicKey key(file);
    EXPECT_TRUE(key.meaningful());

    const std::string orig = key.write();

    // Assignment
    {
        OpenPGP::PublicKey copy;
        copy = key;
        EXPECT_EQ(key, copy);
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

    EXPECT_EQ(key, *key.clone());
}

TEST(Key, Alicepub) {
    std::ifstream file(dir + "Alicepub");
    ASSERT_TRUE(file);

    OpenPGP::Key key(file);
    EXPECT_TRUE(key.meaningful());
}

TEST(PublicKey, Alicepub) {
    std::ifstream file(dir + "Alicepub");
    ASSERT_TRUE(file);

    OpenPGP::PublicKey key(file);
    EXPECT_TRUE(key.meaningful());
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

    // Default constructor
    OpenPGP::SecretKey key;
    EXPECT_NO_THROW(key.read(file));
    EXPECT_TRUE(key.meaningful());

    const std::string orig = key.write();

    // PGP Copy Constructor
    {
        OpenPGP::SecretKey copy((OpenPGP::PGP) key);
        EXPECT_EQ(key, copy);
    }

    // Copy Constructor
    {
        OpenPGP::SecretKey copy(key);
        EXPECT_EQ(key, copy);
    }

    // String Constructor
    {
        OpenPGP::SecretKey str(orig);
        EXPECT_EQ(key, str);
    }

    // Stream Constructor
    {
        file.seekg(0);

        OpenPGP::SecretKey stream(file);
        EXPECT_EQ(key, stream);
    }

    // Move Constructor
    {
        OpenPGP::SecretKey move(std::move(key));
        EXPECT_EQ(key, move);
    }
}

TEST(SecretKey, Assignment) {
    std::ifstream file(dir + "Alicepri");
    ASSERT_TRUE(file);

    OpenPGP::SecretKey key(file);
    EXPECT_TRUE(key.meaningful());

    const std::string orig = key.write();

    // Assignment
    {
        OpenPGP::SecretKey copy;
        copy = key;
        EXPECT_EQ(key, copy);
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

    EXPECT_EQ(key, *key.clone());
}

TEST(Key, Alicepri) {
    std::ifstream file(dir + "Alicepri");
    ASSERT_TRUE(file);

    OpenPGP::Key key(file);
    EXPECT_TRUE(key.meaningful());
}

TEST(PublicKey, AlicePri) {
    std::ifstream file(dir + "Alicepri");
    ASSERT_TRUE(file);

    OpenPGP::PublicKey key(file);
    EXPECT_FALSE(key.meaningful());
}

TEST(SecretKey, Alicepri) {
    std::ifstream file(dir + "Alicepri");
    ASSERT_TRUE(file);

    OpenPGP::SecretKey key(file);
    EXPECT_TRUE(key.meaningful());
}

TEST(SecretKey, PublicKey) {
    std::ifstream pri_file(dir + "Alicepri");
    ASSERT_TRUE(pri_file);

    OpenPGP::SecretKey pri(pri_file);
    EXPECT_TRUE(pri.meaningful());

    std::ifstream pub_file(dir + "Alicepub");
    ASSERT_TRUE(pub_file);

    OpenPGP::PublicKey pub(pub_file);
    EXPECT_TRUE(pub.meaningful());

    // SecretKey -> PublicKey Constructor
    {
        EXPECT_EQ(OpenPGP::PublicKey(pri), pub);
    }

    // SecretKey -> PublicKey Assignment
    {
        OpenPGP::PublicKey key;
        key = pri;
        EXPECT_EQ(key, pub);
    }
}
