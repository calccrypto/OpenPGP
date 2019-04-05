#include <gtest/gtest.h>

#include <fstream>

#include "RevocationCertificate.h"

static const std::string filename = "tests/testvectors/gpg/revoke";

TEST(RevocationCertificate, Constructor) {
    std::ifstream file(filename);
    ASSERT_TRUE(file);

    const std::string orig = trim_whitespace(std::string(std::istreambuf_iterator <char> (file), {}), true, true);
    file.seekg(0);

    // Default constructor
    OpenPGP::RevocationCertificate msg;
    EXPECT_NO_THROW(msg.read(orig));
    EXPECT_TRUE(msg.meaningful());

    // PGP Copy Constructor
    {
        OpenPGP::RevocationCertificate copy((OpenPGP::PGP) msg);
        EXPECT_EQ(orig, copy.write());
    }

    // Copy Constructor
    {
        OpenPGP::RevocationCertificate copy(msg);
        EXPECT_EQ(orig, copy.write());
    }

    // Move Constructor
    {
        OpenPGP::RevocationCertificate move(std::move(msg));
        EXPECT_EQ(orig, move.write());
    }

    // String Constructor
    {
        OpenPGP::RevocationCertificate str(orig);
        EXPECT_EQ(orig, str.write());
    }

    // Stream Constructor
    {
        OpenPGP::RevocationCertificate stream(file);
        EXPECT_EQ(orig, stream.write());
    }
}

TEST(RevocationCertificate, Assignment) {
    std::ifstream file(filename);
    ASSERT_TRUE(file);

    OpenPGP::RevocationCertificate msg(file);
    EXPECT_TRUE(msg.meaningful());

    file.seekg(0);

    const std::string orig = trim_whitespace(std::string(std::istreambuf_iterator <char> (file), {}), true, true);

    // Assignment
    {
        OpenPGP::RevocationCertificate copy;
        copy = msg;
        EXPECT_EQ(orig, copy.write());
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

    OpenPGP::RevocationCertificate::Ptr clone = std::dynamic_pointer_cast <OpenPGP::RevocationCertificate> (msg.clone());
    EXPECT_EQ(msg.write(), clone -> write());
}
