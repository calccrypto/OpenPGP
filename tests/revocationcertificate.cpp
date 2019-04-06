#include <gtest/gtest.h>

#include <fstream>

#include "RevocationCertificate.h"

static const std::string filename = "tests/testvectors/gpg/revoke";

TEST(RevocationCertificate, Constructor) {
    std::ifstream file(filename);
    ASSERT_TRUE(file);

    // Default constructor
    OpenPGP::RevocationCertificate msg;
    EXPECT_NO_THROW(msg.read(file));
    EXPECT_TRUE(msg.meaningful());

    const std::string orig = msg.write();

    // PGP Copy Constructor
    {
        OpenPGP::RevocationCertificate copy((OpenPGP::PGP) msg);
        EXPECT_EQ(msg, copy);
    }

    // Copy Constructor
    {
        OpenPGP::RevocationCertificate copy(msg);
        EXPECT_EQ(msg, copy);
    }

    // String Constructor
    {
        OpenPGP::RevocationCertificate str(orig);
        EXPECT_EQ(msg, str);
    }

    // Stream Constructor
    {
        file.seekg(0);

        OpenPGP::RevocationCertificate stream(file);
        EXPECT_EQ(msg, stream);
    }

    // Move Constructor
    {
        OpenPGP::RevocationCertificate move(std::move(msg));
        EXPECT_EQ(orig, move.write());
    }
}

TEST(RevocationCertificate, Assignment) {
    std::ifstream file(filename);
    ASSERT_TRUE(file);

    OpenPGP::RevocationCertificate msg(file);
    EXPECT_TRUE(msg.meaningful());

    const std::string orig = msg.write();

    // Assignment
    {
        OpenPGP::RevocationCertificate copy;
        copy = msg;
        EXPECT_EQ(msg, copy);
    }

    // Move Assignment
    {
        OpenPGP::RevocationCertificate move;
        move = std::move(msg);
        EXPECT_EQ(orig, move.write());
    }
}

TEST(RevocationCertificate, show) {
    std::ifstream file(filename);
    ASSERT_TRUE(file);

    OpenPGP::RevocationCertificate msg(file);
    EXPECT_TRUE(msg.meaningful());

    EXPECT_NO_THROW(msg.show());
}

TEST(RevocationCertificate, clone) {
    std::ifstream file(filename);
    ASSERT_TRUE(file);

    OpenPGP::RevocationCertificate msg(file);
    EXPECT_TRUE(msg.meaningful());

    EXPECT_EQ(msg, *msg.clone());
}
